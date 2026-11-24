// Copyright 2026 The Beneficial AI Foundation
// SPDX-License-Identifier: AGPL-3.0-only

//! Test drivers that deliver tampered `Hdr` and `Ct2` chunks (feature `monitor`). Each tampered
//! chunk is logged with a `tamper` event. Honest runs pass every MAC check, so only such runs show
//! whether the code acts on a failed check.
//!
//! - `tamper_chaos` tampers with chunks that complete the receiver's decoder, so that the `recv`
//!   of the tampered chunk runs the MAC check.
//! - `tamper_early` tampers with a chunk that does not complete the decoder, so that a later
//!   `recv` of the same epoch runs the MAC check.

use std::collections::VecDeque;

use rand::prelude::*;
use rand::rngs::OsRng;
use rand_core::CryptoRng;

use super::OrchestratorBase;
use crate::encoding::Chunk;
use crate::test::messaging_scka::{GenericMessagingScka, MessagingCkaVulnerability, MessagingScka};
use crate::v1::chunked::states::{Message, MessagePayload, States};
use crate::{Epoch, Error};

type Cka = GenericMessagingScka<States>;

/// A copy of `m`.
fn copy_msg(m: &Message) -> Message {
    let payload = match &m.payload {
        MessagePayload::None => MessagePayload::None,
        MessagePayload::Hdr(c) => MessagePayload::Hdr(*c),
        MessagePayload::Ek(c) => MessagePayload::Ek(*c),
        MessagePayload::EkCt1Ack(c) => MessagePayload::EkCt1Ack(*c),
        MessagePayload::Ct1Ack(b) => MessagePayload::Ct1Ack(*b),
        MessagePayload::Ct1(c) => MessagePayload::Ct1(*c),
        MessagePayload::Ct2(c) => MessagePayload::Ct2(*c),
    };
    Message {
        epoch: m.epoch,
        payload,
    }
}

/// The kinds of chunk that the drivers tamper with.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Hdr,
    Ct2,
}

/// The kind of `m` if it is a `Hdr` or `Ct2` message.
fn kind(m: &Message) -> Option<Kind> {
    match &m.payload {
        MessagePayload::Hdr(_) => Some(Kind::Hdr),
        MessagePayload::Ct2(_) => Some(Kind::Ct2),
        _ => None,
    }
}

/// A copy of the `Hdr` or `Ct2` message `m` with one random byte of the chunk changed.
fn tampered<R: CryptoRng>(m: &Message, rng: &mut R) -> Message {
    let mut t = copy_msg(m);
    let c: &mut Chunk = match &mut t.payload {
        MessagePayload::Hdr(c) | MessagePayload::Ct2(c) => c,
        _ => unreachable!("only Hdr and Ct2 chunks are tampered with"),
    };
    let i = rng.next_u32() as usize % c.data.len();
    c.data[i] ^= rng.random_range(1..=255u8);
    t
}

/// Whether `m` is a `Hdr` chunk and `state` is `NoHeaderReceived`, or `m` is a `Ct2` chunk and
/// `state` is `EkSentCt1Received`, with `state` in the epoch of `m`. In these states `recv` adds
/// the chunk to the state's decoder.
fn decodes(state: &States, m: &Message) -> bool {
    matches!(
        (crate::monitor::state_info(state), kind(m)),
        (("NoHeaderReceived", ep), Some(Kind::Hdr))
            | (("EkSentCt1Received", ep), Some(Kind::Ct2)) if ep == m.epoch
    )
}

/// The result of a dry run of `recv` of `m` from `state`, with no events written: `None` when
/// the `recv` fails, `Some(true)` when it changes the state's name or epoch, `Some(false)`
/// otherwise.
fn dry_run(state: &States, m: &Message) -> Option<bool> {
    let pre = crate::monitor::state_info(state);
    let r = crate::monitor::paused(|| state.clone().recv(m));
    r.ok().map(|r| crate::monitor::state_info(&r.state) != pre)
}

/// Counts of tampered deliveries.
#[derive(Default, Debug)]
struct Stats {
    /// The code returned an error.
    rejected: usize,
    /// The code accepted the tampered chunk.
    accepted: usize,
}

impl OrchestratorBase<Cka> {
    fn agent(&self, is_alex: bool) -> &Cka {
        if is_alex {
            &self.alex
        } else {
            &self.blake
        }
    }

    fn incoming(&self, is_alex: bool) -> &VecDeque<Message> {
        if is_alex {
            &self.b2a_msg_queue
        } else {
            &self.a2b_msg_queue
        }
    }

    /// Logs a `tamper` event for the tampered copy `t` of `orig` and receives `t`, which is not
    /// taken from the queue. Records the key that `messaging_scka_recv` outputs, if any. Returns
    /// whether the code accepted `t`.
    fn receive_tampered(&mut self, is_alex: bool, orig: &Message, t: &Message) -> bool {
        crate::monitor::set_party(is_alex);
        crate::monitor::tamper(orig, t);
        let (agent, _iq, _oq, key_history) = self.data_for_agent(is_alex);
        let Ok(out) = agent.messaging_scka_recv(t, &mut OsRng) else {
            return false;
        };
        if let Some((_ep, key)) = out {
            key_history.push(key);
            let ep = agent.last_emitted_epoch();
            if is_alex {
                self.last_emitted_epoch_a = ep;
            } else {
                self.last_emitted_epoch_b = ep;
            }
        }
        true
    }

    /// Receives the `i`-th message of the queue. With probability `prob`, when it is a `Hdr` or
    /// `Ct2` chunk that completes the decoder of the receiver's state (`decodes` holds and the
    /// dry run changes the state), first receives a tampered copy. If the code rejects the copy,
    /// receives the original; if it accepts the copy, drops the original.
    fn receive_at_tampering<R: CryptoRng>(
        &mut self,
        is_alex: bool,
        i: usize,
        prob: f64,
        stats: &mut Stats,
        rng: &mut R,
    ) -> Result<(), Error> {
        let msg = &self.incoming(is_alex)[i];
        let state = self.agent(is_alex).scka();
        if decodes(state, msg) && rng.random_bool(prob) && dry_run(state, msg) == Some(true) {
            let orig = copy_msg(msg);
            let t = tampered(&orig, rng);
            if self.receive_tampered(is_alex, &orig, &t) {
                stats.accepted += 1;
                self.drop_message_at(is_alex, i);
                return Ok(());
            }
            stats.rejected += 1;
        }
        self.receive_at(is_alex, i).map(|_| ())
    }
}

/// The `chaos` driver, where each delivery of a `Hdr` or `Ct2` chunk that completes the
/// decoder is replaced, with probability `prob`, by a tampered copy. The original is delivered
/// only if the code rejects the copy. Asserts that the code rejects at least one tampered copy.
pub fn tamper_chaos<R: CryptoRng>(num_ticks: usize, prob: f64, rng: &mut R) -> Result<(), Error> {
    let mut stats = Stats::default();
    super::chaos_with::<Cka, R>(num_ticks, rng, |orchestrator, is_alex, i, rng| {
        orchestrator.receive_at_tampering(is_alex, i, prob, &mut stats, rng)
    })?;
    println!("tampered chunks: {stats:?}");
    assert!(stats.rejected > 0, "no tampered chunk was rejected");
    Ok(())
}

/// Runs `sessions` sessions of `num_ticks` ticks. In each tick a random party sends a message
/// and the other party receives its whole queue in order. In each session the first `Hdr`
/// chunk (even sessions) or `Ct2` chunk (odd sessions) that does not complete the decoder is
/// replaced by a tampered copy. Asserts that the code accepts the copy, that the party that
/// received it (the victim) later fails a MAC check on a chunk of the same kind and epoch, and that
/// the keys of both parties agree. Any other error ends the test.
pub fn tamper_early<R: CryptoRng>(
    sessions: usize,
    num_ticks: usize,
    rng: &mut R,
) -> Result<(), Error> {
    for s in 0..sessions {
        let target = if s % 2 == 0 { Kind::Hdr } else { Kind::Ct2 };
        let mut orchestrator = OrchestratorBase::<Cka>::new(rng)?;
        // The party that received the tampered chunk, and the chunk's epoch.
        let mut victim: Option<(bool, Epoch)> = None;
        let mut mac_failures = 0usize;
        for _ in 0..num_ticks {
            let sender = rng.random_bool(0.5);
            orchestrator.send(sender, rng)?;
            let is_alex = !sender;
            while let Some(msg) = orchestrator.incoming(is_alex).front() {
                let state = orchestrator.agent(is_alex).scka();
                if victim.is_none()
                    && kind(msg) == Some(target)
                    && decodes(state, msg)
                    && dry_run(state, msg) == Some(false)
                {
                    let orig = copy_msg(msg);
                    let t = tampered(&orig, rng);
                    orchestrator.drop_message_at(is_alex, 0);
                    assert!(
                        orchestrator.receive_tampered(is_alex, &orig, &t),
                        "a tampered chunk that does not complete the decoder was rejected"
                    );
                    victim = Some((is_alex, orig.epoch));
                    continue;
                }
                let target_chunk =
                    kind(msg) == Some(target) && victim == Some((is_alex, msg.epoch));
                match orchestrator.receive_in_order(is_alex) {
                    Ok(_) => {}
                    Err(Error::MacVerifyFailed) if target_chunk => mac_failures += 1,
                    Err(e) => return Err(e),
                }
            }
            orchestrator.key_history_is_consistent();
        }
        let Some((v, ep)) = victim else {
            panic!("session {s}: no {target:?} chunk was tampered");
        };
        let party = if v { "A" } else { "B" };
        println!("session {s}: tampered {target:?} chunk of party {party}, epoch {ep}, MAC failures {mac_failures}");
        assert!(
            mac_failures > 0,
            "session {s}: the victim never failed a MAC check"
        );
    }
    Ok(())
}
