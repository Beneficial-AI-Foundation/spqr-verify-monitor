// Copyright 2026 The Beneficial AI Foundation
// SPDX-License-Identifier: AGPL-3.0-only

//! Event log for the runtime monitor (feature `monitor`).
//!
//! Each event is one JSON line `{"s":..,"p":..,"op":..,"f":..,"args":..,"ret":..}`: the session
//! number, the party (`A` or `B`), the operation number, the function name, its arguments and
//! its result, with bytes as lowercase hex. Operation 0 is a party's initialization; the test
//! harness starts operation `n + 1` before each `States::send` or `States::recv` call
//! (`begin_op`), and the call's step event ends it. The log is written only when the environment variable `SPQR_MONITOR_DIR`
//! names a directory and the current thread has a party set (`set_party`). The file is
//! `$SPQR_MONITOR_DIR/<thread name>.jsonl`. The Lean program `spqr-monitor` checks the log
//! against `BraidModel`.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::io::Write as _;

use crate::encoding::polynomial::PolyDecoder;
#[cfg(test)]
use crate::encoding::Chunk;
use crate::encoding::Decoder;
use crate::incremental_mlkem768::Keys;
#[cfg(test)]
use crate::v1::chunked::states::{Message, MessagePayload, Recv, Send, States};
#[cfg(test)]
use crate::{EpochSecret, Error};

#[derive(Default)]
struct Sink {
    session: u64,
    op: u64,
    party: Option<char>,
    out: Option<std::io::BufWriter<std::fs::File>>,
    disabled: bool,
}

impl Sink {
    #[cfg(test)]
    fn flush(&mut self) {
        if let Some(out) = self.out.as_mut() {
            out.flush().expect("monitor: cannot flush the event log");
        }
    }

    fn open(&mut self) -> bool {
        if self.out.is_some() {
            return true;
        }
        if self.disabled {
            return false;
        }
        let Some(dir) = std::env::var_os("SPQR_MONITOR_DIR") else {
            self.disabled = true;
            return false;
        };
        let name = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .replace("::", ".");
        std::fs::create_dir_all(&dir).expect("monitor: cannot create SPQR_MONITOR_DIR");
        let path = std::path::Path::new(&dir).join(format!("{name}.jsonl"));
        let file = std::fs::File::create(&path).expect("monitor: cannot create the event log");
        self.out = Some(std::io::BufWriter::new(file));
        true
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        if let Some(out) = self.out.as_mut() {
            let _ = out.flush();
        }
    }
}

thread_local! {
    static SINK: RefCell<Sink> = RefCell::new(Sink::default());
}

#[cfg(test)]
/// Start a new session on this thread. Later events carry the new session number.
pub fn start_session() {
    SINK.with(|s| {
        let mut s = s.borrow_mut();
        s.flush();
        s.session += 1;
        s.op = 0;
        s.party = None;
    });
}

#[cfg(test)]
/// End the session on this thread: no party is set and the log is flushed.
pub fn end_session() {
    SINK.with(|s| {
        let mut s = s.borrow_mut();
        s.party = None;
        s.flush();
    });
}

/// Start the next operation of the session: the events up to the next step event belong to it.
#[cfg(test)]
pub fn begin_op() {
    SINK.with(|s| s.borrow_mut().op += 1);
}

/// Set the party whose calls the following events record.
#[cfg(test)]
pub fn set_party(is_a: bool) {
    SINK.with(|s| s.borrow_mut().party = Some(if is_a { 'A' } else { 'B' }));
}

fn emit(f: &str, args: &str, ret: &str) {
    SINK.with(|s| {
        let mut s = s.borrow_mut();
        let Some(p) = s.party else { return };
        if !s.open() {
            return;
        }
        let (session, op) = (s.session, s.op);
        let out = s.out.as_mut().expect("opened above");
        writeln!(
            out,
            "{{\"s\":{session},\"p\":\"{p}\",\"op\":{op},\"f\":\"{f}\",\"args\":{args},\"ret\":{ret}}}"
        )
        .expect("monitor: cannot write the event log");
    });
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 * bytes.len() + 2);
    s.push('"');
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String");
    }
    s.push('"');
    s
}

fn list(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}

/// The pre-trace: the role and the shared authentication key a party starts from.
pub fn init(role: &str, auth_key: &[u8]) {
    emit(
        "init",
        &list(&[format!("\"{role}\""), hex(auth_key)]),
        "null",
    );
}

/// `hkdf_to_slice(salt, ikm, info, okm)` wrote `okm`.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &[u8]) {
    emit(
        "hkdf",
        &list(&[hex(salt), hex(ikm), hex(info), okm.len().to_string()]),
        &hex(okm),
    );
}

/// `libcrux_hmac::hmac`, with an event for each call.
pub fn hmac(
    alg: libcrux_hmac::Algorithm,
    key: &[u8],
    data: &[u8],
    tag_length: Option<usize>,
) -> Vec<u8> {
    let tag = libcrux_hmac::hmac(alg, key, data, tag_length);
    emit("hmac", &list(&[hex(key), hex(data)]), &hex(&tag));
    tag
}

/// `generate` drew `seed` and returned `keys`.
pub fn generate(seed: &[u8], keys: &Keys) {
    emit(
        "mlkem.generate",
        &list(&[hex(seed)]),
        &list(&[hex(&keys.dk), hex(&keys.hdr), hex(&keys.ek)]),
    );
}

/// `encaps1(hdr)` drew `randomness` and returned `(ct1, es, ss)`.
pub fn encaps1(hdr: &[u8], randomness: &[u8], ct1: &[u8], es: &[u8], ss: &[u8]) {
    emit(
        "mlkem.encaps1",
        &list(&[hex(hdr), hex(randomness)]),
        &list(&[hex(es), hex(ct1), hex(ss)]),
    );
}

/// `encaps2(ek, es)` returned `ct2`. `es` is the argument, before the libcrux issue 1275 fix.
pub fn encaps2(ek: &[u8], es: &[u8], ct2: &[u8]) {
    emit("mlkem.encaps2", &list(&[hex(ek), hex(es)]), &hex(ct2));
}

/// `decaps(dk, ct1, ct2)` returns `ss`: log it and return it.
pub fn decaps<T: AsRef<[u8]>>(dk: &[u8], ct1: &[u8], ct2: &[u8], ss: T) -> T {
    emit(
        "mlkem.decaps",
        &list(&[hex(dk), hex(ct1), hex(ct2)]),
        &hex(ss.as_ref()),
    );
    ss
}

/// `ek_matches_header(ek, hdr)` returns `ok`: log it and return it.
pub fn ek_matches_header(ek: &[u8], hdr: &[u8], ok: bool) -> bool {
    emit(
        "mlkem.ek_matches_header",
        &list(&[hex(ek), hex(hdr)]),
        if ok { "true" } else { "false" },
    );
    ok
}

/// The decoder's `decoded_message()` at a call site of the chunked state machine.
pub fn decoded(decoder: &PolyDecoder) {
    let ret = match decoder.decoded_message() {
        Some(m) => hex(&m),
        None => "null".to_string(),
    };
    emit(
        "decoder.message",
        &list(&[decoder.get_pts_needed().to_string()]),
        &ret,
    );
}

#[cfg(test)]
/// The variant name and epoch of a state.
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

#[cfg(test)]
fn chunk_fields(kind: &str, c: &Chunk) -> String {
    format!(
        "\"kind\":\"{kind}\",\"index\":{},\"data\":{}",
        c.index,
        hex(&c.data)
    )
}

#[cfg(test)]
fn message(m: &Message) -> String {
    let payload = match &m.payload {
        MessagePayload::None => "\"kind\":\"none\"".to_string(),
        MessagePayload::Hdr(c) => chunk_fields("hdr", c),
        MessagePayload::Ek(c) => chunk_fields("ek", c),
        MessagePayload::EkCt1Ack(c) => chunk_fields("ekct1ack", c),
        MessagePayload::Ct1Ack(true) => "\"kind\":\"ct1ack\"".to_string(),
        MessagePayload::Ct1Ack(false) => "\"kind\":\"ct1ackfalse\"".to_string(),
        MessagePayload::Ct1(c) => chunk_fields("ct1", c),
        MessagePayload::Ct2(c) => chunk_fields("ct2", c),
    };
    format!("{{\"epoch\":{},{payload}}}", m.epoch)
}

#[cfg(test)]
fn key(k: &Option<EpochSecret>) -> String {
    match k {
        None => "null".to_string(),
        Some(k) => format!("{{\"epoch\":{},\"secret\":{}}}", k.epoch, hex(&k.secret)),
    }
}

#[cfg(test)]
fn state_args(pre: (&'static str, u64)) -> String {
    format!("\"{}\",{}", pre.0, pre.1)
}

#[cfg(test)]
/// `States::send` from a state named `pre` returned `r`.
pub fn send_step(pre: (&'static str, u64), r: &Result<Send, Error>) {
    let ret = match r {
        Ok(s) => {
            let (name, ep) = state_info(&s.state);
            format!(
                "{{\"state\":\"{name}\",\"epoch\":{ep},\"msg\":{},\"key\":{}}}",
                message(&s.msg),
                key(&s.key)
            )
        }
        Err(e) => format!("{{\"err\":\"{}\"}}", format!("{e:?}").replace('"', "'")),
    };
    emit("States::send", &format!("[{}]", state_args(pre)), &ret);
}

#[cfg(test)]
/// `States::recv` of `msg` from a state named `pre` returned `r`.
pub fn recv_step(pre: (&'static str, u64), msg: &Message, r: &Result<Recv, Error>) {
    let ret = match r {
        Ok(s) => {
            let (name, ep) = state_info(&s.state);
            format!(
                "{{\"state\":\"{name}\",\"epoch\":{ep},\"key\":{}}}",
                key(&s.key)
            )
        }
        Err(e) => format!("{{\"err\":\"{}\"}}", format!("{e:?}").replace('"', "'")),
    };
    emit(
        "States::recv",
        &format!("[{},{}]", state_args(pre), message(msg)),
        &ret,
    );
}
