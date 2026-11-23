// Copyright 2026 The Beneficial AI Foundation
// SPDX-License-Identifier: AGPL-3.0-only

//! Event log for the runtime monitor (feature `monitor`).
//!
//! Each event is one JSON line `{"s":..,"p":..,"op":..,"f":..,"args":..,"ret":..}`: the session
//! number, the party (`A` or `B`), the operation number, the function name, its arguments and
//! its result, with bytes as lowercase hex strings. The operation number counts per session and
//! is shared by both parties. Operation 0 is the initialization of both parties; the test
//! harness starts operation `n + 1` before each `States::send` or `States::recv` call
//! (`begin_op`), and the `States::send` or `States::recv` event is the last event of that
//! operation. A test that tampers with a message in transit writes a `tamper` event in the
//! operation of the `recv` that receives the tampered message.
//!
//! An event is written only when the environment variable `SPQR_MONITOR_DIR` is set and the
//! current thread has a party set (`set_party`). Each thread writes to
//! `$SPQR_MONITOR_DIR/<thread name>.jsonl`, with `::` in the thread name replaced by `.`; the
//! directory is created if it does not exist. The functions panic if the log cannot be written.
//! A log has no end marker: a log that stops early, for example because the test failed, is
//! checked as the prefix that it holds. The Lean program `spqr-monitor` checks the log against
//! `BraidModel`.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufWriter, Write as _};

use crate::encoding::polynomial::PolyDecoder;
#[cfg(test)]
use crate::encoding::Chunk;
use crate::encoding::Decoder;
use crate::incremental_mlkem768::Keys;
#[cfg(test)]
use crate::v1::chunked::states::{Message, MessagePayload, Recv, Send, States};
#[cfg(test)]
use crate::{EpochSecret, Error};

/// Appends formatted text to a `String`. Writing to a `String` cannot fail.
macro_rules! push {
    ($out:expr, $($arg:tt)*) => {{
        let _ = write!($out, $($arg)*);
    }};
}

/// The output file of a thread's log.
#[derive(Default)]
enum Log {
    /// No event has been written yet.
    #[default]
    Unopened,
    /// `SPQR_MONITOR_DIR` is not set.
    Off,
    On(BufWriter<File>),
}

impl Log {
    /// The output file, opened on the first call.
    fn get(&mut self) -> Option<&mut BufWriter<File>> {
        if let Log::Unopened = self {
            *self = match std::env::var_os("SPQR_MONITOR_DIR") {
                None => Log::Off,
                Some(dir) => {
                    let name = std::thread::current()
                        .name()
                        .unwrap_or("unnamed")
                        .replace("::", ".");
                    std::fs::create_dir_all(&dir).expect("monitor: cannot create SPQR_MONITOR_DIR");
                    let path = std::path::Path::new(&dir).join(format!("{name}.jsonl"));
                    let file = File::create(&path).unwrap_or_else(|e| {
                        panic!("monitor: cannot create {}: {e}", path.display())
                    });
                    Log::On(BufWriter::new(file))
                }
            };
        }
        match self {
            Log::On(out) => Some(out),
            _ => None,
        }
    }
}

#[derive(Default)]
struct Sink {
    session: u64,
    op: u64,
    party: Option<char>,
    log: Log,
}

impl Sink {
    #[cfg(test)]
    fn flush(&mut self) {
        if let Log::On(out) = &mut self.log {
            out.flush().expect("monitor: cannot flush the event log");
        }
    }
}

thread_local! {
    static SINK: RefCell<Sink> = RefCell::new(Sink::default());
}

/// Starts a new session on this thread: increments the session number, resets the operation
/// number to 0, clears the party and flushes the log.
#[cfg(test)]
pub fn start_session() {
    SINK.with(|s| {
        let mut s = s.borrow_mut();
        s.flush();
        s.session += 1;
        s.op = 0;
        s.party = None;
    });
}

/// Ends the session on this thread: clears the party and flushes the log.
#[cfg(test)]
pub fn end_session() {
    SINK.with(|s| {
        let mut s = s.borrow_mut();
        s.party = None;
        s.flush();
    });
}

/// Increments the operation number of the session.
#[cfg(test)]
pub fn begin_op() {
    SINK.with(|s| s.borrow_mut().op += 1);
}

/// Sets the party of the events that follow: `A` if `is_a`, else `B`.
#[cfg(test)]
pub fn set_party(is_a: bool) {
    SINK.with(|s| s.borrow_mut().party = Some(if is_a { 'A' } else { 'B' }));
}

/// Runs `f` with no events written.
#[cfg(test)]
pub fn paused<T>(f: impl FnOnce() -> T) -> T {
    let party = SINK.with(|s| s.borrow_mut().party.take());
    let r = f();
    SINK.with(|s| s.borrow_mut().party = party);
    r
}

fn emit(f: &str, args: impl FnOnce(&mut String), ret: impl FnOnce(&mut String)) {
    emit_at(0, f, args, ret)
}

/// Writes an event for function `f` in operation `op + offset`, where `op` is the current
/// operation. `args` and `ret` append the JSON of the arguments and the result; they run only
/// when the event is written.
fn emit_at(offset: u64, f: &str, args: impl FnOnce(&mut String), ret: impl FnOnce(&mut String)) {
    let header = SINK.with(|s| {
        let mut s = s.borrow_mut();
        let p = s.party?;
        s.log.get()?;
        Some((s.session, p, s.op + offset))
    });
    let Some((session, p, op)) = header else {
        return;
    };
    let mut line = String::with_capacity(256);
    push!(
        line,
        "{{\"s\":{session},\"p\":\"{p}\",\"op\":{op},\"f\":\"{f}\",\"args\":"
    );
    args(&mut line);
    line.push_str(",\"ret\":");
    ret(&mut line);
    line.push_str("}\n");
    SINK.with(|s| {
        let mut s = s.borrow_mut();
        let out = s.log.get().expect("the log is open");
        out.write_all(line.as_bytes())
            .expect("monitor: cannot write the event log");
    });
}

/// Appends `bytes` as a JSON string of lowercase hex digits.
fn hex(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    out.reserve(2 * bytes.len() + 2);
    out.push('"');
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    out.push('"');
}

/// Appends a JSON array of the hex strings of `items`.
fn hex_list(out: &mut String, items: &[&[u8]]) {
    out.push('[');
    for (i, bytes) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        hex(out, bytes);
    }
    out.push(']');
}

/// Logs the initialization of a party with role `role` (`"a"` or `"b"`) and authentication key
/// `auth_key`.
pub fn init(role: &str, auth_key: &[u8]) {
    emit(
        "init",
        |o| {
            push!(o, "[\"{role}\",");
            hex(o, auth_key);
            o.push(']');
        },
        |o| o.push_str("null"),
    );
}

/// Logs a call `hkdf_to_slice(salt, ikm, info, okm)`: the arguments are `salt`, `ikm`, `info`
/// and the length of `okm`, the result is `okm`.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &[u8]) {
    emit(
        "hkdf",
        |o| {
            o.push('[');
            for part in [salt, ikm, info] {
                hex(o, part);
                o.push(',');
            }
            push!(o, "{}]", okm.len());
        },
        |o| hex(o, okm),
    );
}

/// Calls `libcrux_hmac::hmac` and logs `key` and `data` as the arguments and the tag as the
/// result. `alg` and `tag_length` are not logged.
pub fn hmac(
    alg: libcrux_hmac::Algorithm,
    key: &[u8],
    data: &[u8],
    tag_length: Option<usize>,
) -> Vec<u8> {
    let tag = libcrux_hmac::hmac(alg, key, data, tag_length);
    emit("hmac", |o| hex_list(o, &[key, data]), |o| hex(o, &tag));
    tag
}

/// Logs a call of `incremental_mlkem768::generate` that drew `seed` and returned `keys`. The
/// result is `[dk, hdr, ek]`.
pub fn generate(seed: &[u8], keys: &Keys) {
    emit(
        "mlkem.generate",
        |o| hex_list(o, &[seed]),
        |o| hex_list(o, &[&keys.dk, &keys.hdr, &keys.ek]),
    );
}

/// Logs a call `encaps1(hdr)` that drew `randomness` and returned `ct1`, the encapsulation state
/// `es` and the shared secret `ss`. The result is `[es, ct1, ss]`.
pub fn encaps1(hdr: &[u8], randomness: &[u8], ct1: &[u8], es: &[u8], ss: &[u8]) {
    emit(
        "mlkem.encaps1",
        |o| hex_list(o, &[hdr, randomness]),
        |o| hex_list(o, &[es, ct1, ss]),
    );
}

/// Logs a call `encaps2(ek, es)` that returned `ct2`, with `es` as the caller passed it.
pub fn encaps2(ek: &[u8], es: &[u8], ct2: &[u8]) {
    emit("mlkem.encaps2", |o| hex_list(o, &[ek, es]), |o| hex(o, ct2));
}

/// Logs a call `decaps(dk, ct1, ct2)` that returned `ss`, and returns `ss`.
pub fn decaps<T: AsRef<[u8]>>(dk: &[u8], ct1: &[u8], ct2: &[u8], ss: T) -> T {
    emit(
        "mlkem.decaps",
        |o| hex_list(o, &[dk, ct1, ct2]),
        |o| hex(o, ss.as_ref()),
    );
    ss
}

/// Logs a call `ek_matches_header(ek, hdr)` that returned `ok`, and returns `ok`.
pub fn ek_matches_header(ek: &[u8], hdr: &[u8], ok: bool) -> bool {
    emit(
        "mlkem.ek_matches_header",
        |o| hex_list(o, &[ek, hdr]),
        |o| push!(o, "{ok}"),
    );
    ok
}

/// Logs `decoder.decoded_message()` as the result, with the number of points the decoder needs
/// as the argument. This is a call of its own, apart from the call whose value the code uses.
pub fn decoded(decoder: &PolyDecoder) {
    emit(
        "decoder.message",
        |o| push!(o, "[{}]", decoder.get_pts_needed()),
        |o| match decoder.decoded_message() {
            Some(m) => hex(o, &m),
            None => o.push_str("null"),
        },
    );
}

/// The variant name and epoch of a state.
#[cfg(test)]
pub fn state_info(s: &States) -> (&'static str, u64) {
    match s {
        States::KeysUnsampled(st) => ("KeysUnsampled", st.epoch()),
        States::KeysSampled(st) => ("KeysSampled", st.epoch()),
        States::HeaderSent(st) => ("HeaderSent", st.epoch()),
        States::Ct1Received(st) => ("Ct1Received", st.epoch()),
        States::EkSentCt1Received(st) => ("EkSentCt1Received", st.epoch()),
        States::NoHeaderReceived(st) => ("NoHeaderReceived", st.epoch()),
        States::HeaderReceived(st) => ("HeaderReceived", st.epoch()),
        States::Ct1Sampled(st) => ("Ct1Sampled", st.epoch()),
        States::EkReceivedCt1Sampled(st) => ("EkReceivedCt1Sampled", st.epoch()),
        States::Ct1Acknowledged(st) => ("Ct1Acknowledged", st.epoch()),
        States::Ct2Sampled(st) => ("Ct2Sampled", st.epoch()),
    }
}

/// Appends the JSON object of a message: its epoch, the payload kind and, for a chunk, its index
/// and data.
#[cfg(test)]
fn message(o: &mut String, m: &Message) {
    let (kind, chunk): (&str, Option<&Chunk>) = match &m.payload {
        MessagePayload::None => ("none", None),
        MessagePayload::Hdr(c) => ("hdr", Some(c)),
        MessagePayload::Ek(c) => ("ek", Some(c)),
        MessagePayload::EkCt1Ack(c) => ("ekct1ack", Some(c)),
        MessagePayload::Ct1Ack(true) => ("ct1ack", None),
        MessagePayload::Ct1Ack(false) => ("ct1ackfalse", None),
        MessagePayload::Ct1(c) => ("ct1", Some(c)),
        MessagePayload::Ct2(c) => ("ct2", Some(c)),
    };
    push!(o, "{{\"epoch\":{},\"kind\":\"{kind}\"", m.epoch);
    if let Some(c) = chunk {
        push!(o, ",\"index\":{},\"data\":", c.index);
        hex(o, &c.data);
    }
    o.push('}');
}

/// Appends `null` or the JSON object of an epoch secret.
#[cfg(test)]
fn key(o: &mut String, k: &Option<EpochSecret>) {
    match k {
        None => o.push_str("null"),
        Some(k) => {
            push!(o, "{{\"epoch\":{},\"secret\":", k.epoch);
            hex(o, &k.secret);
            o.push('}');
        }
    }
}

/// Appends the state name and epoch `pre`, without brackets.
#[cfg(test)]
fn state_args(o: &mut String, pre: (&str, u64)) {
    push!(o, "\"{}\",{}", pre.0, pre.1);
}

/// Appends the result of a state transition: `ok` appends the fields after the new state's name
/// and epoch; an error becomes `{"err":..}`, its `Debug` text with `"` replaced by `'`.
#[cfg(test)]
fn step_ret<T>(
    o: &mut String,
    r: &Result<T, Error>,
    state: impl FnOnce(&T) -> &States,
    ok: impl FnOnce(&mut String, &T),
) {
    match r {
        Ok(t) => {
            let (name, ep) = state_info(state(t));
            push!(o, "{{\"state\":\"{name}\",\"epoch\":{ep}");
            ok(o, t);
            o.push('}');
        }
        Err(e) => {
            push!(o, "{{\"err\":\"{}\"}}", format!("{e:?}").replace('"', "'"));
        }
    }
}

/// Logs a call of `States::send` from the state with name and epoch `pre` that returned `r`.
#[cfg(test)]
pub fn send_step(pre: (&'static str, u64), r: &Result<Send, Error>) {
    emit(
        "States::send",
        |o| {
            o.push('[');
            state_args(o, pre);
            o.push(']');
        },
        |o| {
            step_ret(
                o,
                r,
                |s| &s.state,
                |o, s| {
                    o.push_str(",\"msg\":");
                    message(o, &s.msg);
                    o.push_str(",\"key\":");
                    key(o, &s.key);
                },
            )
        },
    );
}

/// Logs a call of `States::recv` of `msg` from the state with name and epoch `pre` that
/// returned `r`.
#[cfg(test)]
pub fn recv_step(pre: (&'static str, u64), msg: &Message, r: &Result<Recv, Error>) {
    emit(
        "States::recv",
        |o| {
            o.push('[');
            state_args(o, pre);
            o.push(',');
            message(o, msg);
            o.push(']');
        },
        |o| {
            step_ret(
                o,
                r,
                |s| &s.state,
                |o, s| {
                    o.push_str(",\"key\":");
                    key(o, &s.key);
                },
            )
        },
    );
}

/// Logs that the network replaced the peer's message `orig` by `tampered`, which the current
/// party receives next. The event is written in the next operation, the one of that `recv`.
#[cfg(test)]
pub fn tamper(orig: &Message, tampered: &Message) {
    emit_at(
        1,
        "tamper",
        |o| {
            o.push('[');
            message(o, orig);
            o.push(',');
            message(o, tampered);
            o.push(']');
        },
        |o| o.push_str("null"),
    );
}
