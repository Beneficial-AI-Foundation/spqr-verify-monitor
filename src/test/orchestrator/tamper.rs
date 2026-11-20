// Copyright 2026 The Beneficial AI Foundation
// SPDX-License-Identifier: AGPL-3.0-only

//! Test drivers that tamper with `Hdr` and `Ct2` chunks in transit, for the runtime monitor
//! (feature `monitor`).
//!
//! Honest runs never deliver a bad MAC, so a monitor of honest traces cannot see a MAC check
//! whose result the code ignores. These drivers deliver tampered chunks and log each one with a
//! `tamper` event (`crate::monitor::tamper`). A `recv` that fails leaves the party in its old
//! state (`GenericMessagingScka::messaging_scka_recv` keeps the old state on an error), and the
//! run goes on.
//!
//! - `tamper_chaos` tampers with chunks that complete a decoder, so that the honest code fails
//!   at the MAC check of that `recv`, and then delivers the original chunk.
//! - `tamper_early` tampers with a chunk that does not complete the decoder. The honest code
//!   accepts it and keeps it in the decoder, and every later decode of that epoch fails at the
//!   MAC check: the party stays in that epoch for the rest of the session.
//!
//! Whether a chunk completes the decoder comes from a dry run on a clone of the receiver's
//! state with the honest chunk and no events written. The dry run does not depend on the MAC
//! check of a tampered chunk.

use rand::prelude::*;
use rand::rngs::OsRng;
use rand_core::CryptoRng;

use super::OrchestratorBase;
use crate::encoding::Chunk;
use crate::test::messaging_scka::{GenericMessagingScka, MessagingCkaVulnerability, MessagingScka};
use crate::v1::chunked::states::{Message, MessagePayload, States};
use crate::Error;

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

/// The kind of a `Hdr` or `Ct2` message.
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

/// Whether `state` adds the chunk of `m` to its decoder: a `Hdr` chunk in `NoHeaderReceived`
/// or a `Ct2` chunk in `EkSentCt1Received`, of the state's epoch. Other states that accept these
/// chunks start a new decoder or ignore them.
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

    /// Receive `msg`, which is not taken from the queue, and record the key it outputs.
    fn deliver(&mut self, is_alex: bool, msg: &Message) -> Result<(), Error> {
        crate::monitor::set_party(is_alex);
        let emitted_ep = {
            let (agent, _iq, _oq, key_history) = self.data_for_agent(is_alex);
            let mut rng = OsRng;
            let out = agent.messaging_scka_recv(msg, &mut rng)?;
            out.map(|(_ep, key)| {
                key_history.push(key);
                agent.last_emitted_epoch()
            })
        };
        if let Some(ep) = emitted_ep {
            if is_alex {
                self.last_emitted_epoch_a = ep;
            } else {
                self.last_emitted_epoch_b = ep;
            }
        }
        Ok(())
    }

    /// Log a tampered copy `t` of `orig` and deliver it. Return whether the code accepted it.
    fn deliver_tampered(&mut self, is_alex: bool, orig: &Message, t: &Message) -> bool {
        crate::monitor::set_party(is_alex);
        crate::monitor::tamper(orig, t);
        self.deliver(is_alex, t).is_ok()
    }

    /// Receive the `i`-th message of the queue. With probability `prob`, when it is a `Hdr` or
    /// `Ct2` chunk that completes the decoder of the state (`decodes` and the dry run changes
    /// the state), first deliver a tampered copy. If the code
    /// rejects the copy, deliver the original; if it accepts the copy, drop the original.
    fn receive_at_tampering<R: CryptoRng>(
        &mut self,
        is_alex: bool,
        i: usize,
        prob: f64,
        stats: &mut Stats,
        rng: &mut R,
    ) -> Result<(), Error> {
        let incoming = if is_alex {
            &self.b2a_msg_queue
        } else {
            &self.a2b_msg_queue
        };
        let msg = &incoming[i];
        let state = self.agent(is_alex).scka();
        if decodes(state, msg) && rng.random_bool(prob) && dry_run(state, msg) == Some(true) {
            let orig = copy_msg(msg);
            let t = tampered(&orig, rng);
            if self.deliver_tampered(is_alex, &orig, &t) {
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
/// decoder is tampered with probability `prob`.
pub fn tamper_chaos<R: CryptoRng>(num_ticks: usize, prob: f64, rng: &mut R) -> Result<(), Error> {
    let ooo_prob = 0.7;
    let send_limit = 10;
    let drop_message_prob = 0.1;
    let mut stats = Stats::default();
    let mut orchestrator = OrchestratorBase::<Cka>::new(rng)?;
    for i in 0..num_ticks {
        let use_alex = if i % 100 < 50 {
            rng.random_bool(0.25)
        } else {
            rng.random_bool(0.75)
        };
        if rng.random_bool(ooo_prob) {
            let qlen = orchestrator.qlen(use_alex);
            if qlen > 0 {
                let at = rng.next_u32() as usize % qlen;
                orchestrator.receive_at_tampering(use_alex, at, prob, &mut stats, rng)?;
            }
        }
        let num_to_send = rng.next_u32() % send_limit;
        for _ in 0..num_to_send {
            orchestrator.send(use_alex, rng)?;
            if rng.random_bool(drop_message_prob) {
                orchestrator.drop_message_at(use_alex, 0);
            }
        }
        loop {
            let qlen = orchestrator.qlen(use_alex);
            if qlen <= 20 {
                break;
            }
            let at = rng.next_u32() as usize % qlen;
            orchestrator.receive_at_tampering(use_alex, at, prob, &mut stats, rng)?;
        }
        orchestrator.key_history_is_consistent();
    }
    orchestrator.print_key_history_lengths();
    println!("tampered chunks: {stats:?}");
    assert!(stats.rejected > 0, "no tampered chunk was rejected");
    Ok(())
}

/// Sessions of `num_ticks` ticks where one `Hdr` or `Ct2` chunk that does not complete the
/// decoder is replaced by a tampered copy. In each tick one random party sends a message and the
/// other party receives its whole queue in order. The party that received the tampered chunk
/// (the victim) must fail at least once later, and the keys of both parties must agree.
pub fn tamper_early<R: CryptoRng>(
    sessions: usize,
    num_ticks: usize,
    rng: &mut R,
) -> Result<(), Error> {
    for s in 0..sessions {
        let target = if s % 2 == 0 { Kind::Hdr } else { Kind::Ct2 };
        let mut orchestrator = OrchestratorBase::<Cka>::new(rng)?;
        let mut victim: Option<bool> = None;
        let mut victim_errors = 0usize;
        for _ in 0..num_ticks {
            let sender = rng.random_bool(0.5);
            orchestrator.send(sender, rng)?;
            let is_alex = !sender;
            while orchestrator.qlen(is_alex) > 0 {
                let incoming = if is_alex {
                    &mut orchestrator.b2a_msg_queue
                } else {
                    &mut orchestrator.a2b_msg_queue
                };
                let msg = incoming.pop_front().expect("queue is not empty");
                let state = orchestrator.agent(is_alex).scka();
                if victim.is_none()
                    && kind(&msg) == Some(target)
                    && decodes(state, &msg)
                    && dry_run(state, &msg) == Some(false)
                {
                    let t = tampered(&msg, rng);
                    assert!(
                        orchestrator.deliver_tampered(is_alex, &msg, &t),
                        "a tampered chunk that does not complete the decoder was rejected"
                    );
                    victim = Some(is_alex);
                    continue;
                }
                match orchestrator.deliver(is_alex, &msg) {
                    Ok(()) => {}
                    Err(_) if victim == Some(is_alex) => victim_errors += 1,
                    Err(e) => return Err(e),
                }
            }
            orchestrator.key_history_is_consistent();
        }
        println!("session {s}: tampered {target:?} chunk, victim errors {victim_errors}");
        assert!(
            victim.is_some(),
            "session {s}: no {target:?} chunk was tampered"
        );
        assert!(victim_errors > 0, "session {s}: the victim never failed");
    }
    Ok(())
}
