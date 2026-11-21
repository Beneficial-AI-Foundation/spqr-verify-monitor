# Review request: tampering test driver for the SPQR runtime monitor

Repository: the current directory (Rust crate `spqr` plus Lean 4 monitor under `Monitor/`). You can read any file.

## Context
A runtime monitor (cargo feature `monitor`) logs each party's `States::send`/`States::recv` calls and primitive calls (HKDF, HMAC, ML-KEM, decoder results) as JSON lines (`src/monitor.rs`). The Lean program `Monitor/Main.lean` + `Monitor/Check.lean` replays each party through a verified checker `BraidModel.checkRun` (`Spqr/Specs/Braid/StateMachine/Monitor.lean`). It has `Obs.recvErr`: a failed code `recv` is accepted only when the model's `Receive()` also fails, and the state stays. `sessionChecks` (Check.lean) checks delivery: each received message must equal an unconsumed earlier send of the peer.

## Goal of the change (commit f6e62a5, `git show f6e62a5`)
Mutant R4 (`let _ = auth.verify_ct(epoch, &ct1, &mac);` instead of `...?;` in `src/v1/unchunked/send_ek.rs`) passes `cargo test` and the monitor accepted its honest traces, because honest runs never deliver a bad MAC. The change adds adversarial tests so that the monitor sees a failing MAC:

- `src/test/orchestrator/tamper.rs`: `tamper_chaos` (chaos driver; for a Hdr chunk in NoHeaderReceived or a Ct2 chunk in EkSentCt1Received of the same epoch, with probability 0.3, a dry run of `recv` on a clone of the receiver's `States`, events paused, with the honest chunk; if it changes state name or epoch, the chunk completes the decoder; then one random byte of a copy is XORed, a `tamper` event is logged, the copy delivered; error expected; original delivered afterwards; if the copy is accepted the original is dropped). `tamper_early` (short sessions, in-order delivery; the first non-completing Hdr/Ct2 chunk of a decoding state is replaced by a tampered copy; the victim then fails at every later decode of that epoch; errors of the victim are tolerated; asserts at least one victim error and key agreement).
- `src/monitor.rs`: `paused`, `emit_at`, `tamper` (event in the operation number of the following recv).
- `src/test/messaging_scka.rs`: `scka()` accessor.
- `Monitor/Check.lean`: `tamperedCopy` and handling of `tamper` events in `sessionChecks`: original must be an unconsumed send of the peer; copy same epoch, payload kind, chunk index, chunk length, different bytes; then the copy counts as one more send of the peer.
- `src/v1.rs`: two tests under `#[cfg(feature = "monitor")]`.

Out of scope: changing BraidModel or the theorems.

## Results so far
Unmutated: 57 tests pass without the feature, 59 with it; monitor accepts all 13 traces (36 parties). R4 mutant: 57 pass without the feature; with the feature the two tamper tests fail their own key-agreement assertion; the monitor rejects the tamper traces with "the model's Receive() fails, the code accepted". Forged tamper events (original not sent; copy with another index) fail the delivery check.

## What to review
Correctness bugs in the Rust driver and the Lean delivery-check change; whether the monitor's acceptance of tampered traces is sound (can a tamper event hide a real delivery error or a real bug?); whether the dry-run oracle is independent of the code under test in a way that matters for R4; whether the tests could be flaky; departures from standard Rust/Lean practice; unclear doc comments. Cite file:line. Concrete issues only, no stylistic nitpicks. Finish with a prioritized list (HIGH/MEDIUM/LOW).

## Diff
```diff
commit f6e62a5f7c67d78873bb691aa5c42fc6929bbf0e
Author: astefano <lacramioara.astefanoaei@gmail.com>
Date:   Thu Nov 19 21:15:19 2026 +0100

    Add tests that tamper with header and ciphertext chunks in transit
    
    Honest runs never deliver a bad MAC, so the monitor could not see a MAC
    check whose result the code drops. Two monitor-only tests now deliver
    tampered Hdr and Ct2 chunks: one tampers with the chunk that completes
    the decoder and then delivers the original, the other tampers with an
    earlier chunk so that the party fails at every later decode of that
    epoch. A failed recv keeps the party's old state, and the run goes on.
    
    Each tampered delivery is logged as a tamper event. The delivery check
    accepts the tampered copy only if the original is an unconsumed send of
    the peer and the copy differs in the chunk bytes only.
    
    Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

diff --git a/Monitor/Check.lean b/Monitor/Check.lean
index 672ef16..98df29f 100644
--- a/Monitor/Check.lean
+++ b/Monitor/Check.lean
@@ -20,7 +20,8 @@ For each party of a session the monitor:
 
 It also checks that each table entry is a function across the party's operations, and, for the
 session, the delivery of messages, the agreement of keys and the reuse of randomness (not
-covered by the theorems). -/
+covered by the theorems). A `tamper` event (a test changed a message in transit) is not a
+primitive call: the party check skips it, and the delivery check reads it. -/
 
 open Lean Std Aeneas Aeneas.Std BraidModel
 
@@ -387,7 +388,25 @@ structure SessionChecks where
   incompleteEpochs : List Nat
   randomness : Except String Unit
 
-/-- Delivery, key agreement and reuse of randomness for a session's events, in file order. -/
+/-- Whether `t` is a tampered copy of `m`: a chunk message with the same epoch, payload kind,
+chunk index and chunk length, and other chunk bytes. -/
+def tamperedCopy (m t : Msg MChunk) : Bool :=
+  let chunk : Payload MChunk → Option MChunk
+    | .hdr c | .ek c | .ekCt1Ack c | .ct1 c | .ct2 c => some c
+    | _ => none
+  match chunk m.payload, chunk t.payload with
+  | some c, some d =>
+    m.epoch == t.epoch && m.payload.ctorIdx == t.payload.ctorIdx && c.index == d.index &&
+      c.data.length == d.data.length && c.data != d.data
+  | _, _ => false
+
+/-- Delivery, key agreement and reuse of randomness for a session's events, in file order.
+
+Delivery: each receive consumes an equal earlier send of the other party. A `tamper` event of a
+party, with arguments `[orig, copy]`, says that the network made `copy` from `orig` and that the
+party receives `copy` next. `orig` must be an earlier send of the other party that no receive
+consumed, and `copy` a tampered copy of it (`tamperedCopy`). Then `copy` counts as one more send
+of the other party. `orig` stays available. -/
 def sessionChecks (evs : Array Event) (ka kb : List Key) : SessionChecks := Id.run do
   -- delivery: each receive consumes an equal earlier send of the other party
   let mut sent : HashMap (String × String) Nat := {}
@@ -407,6 +426,23 @@ def sessionChecks (evs : Array Event) (ka kb : List Key) : SessionChecks := Id.r
         | some (n + 1) => sent := sent.insert k n
         | _ => delivery := .error s!"line {e.line}: party {e.party} received a message that \
             party {peer} did not send"
+    else if e.f == "tamper" && delivery.isOk then
+      let peer := if e.party == "A" then "B" else "A"
+      match e.args[0]?, e.args[1]? with
+      | some o, some t =>
+        match parseMsg o, parseMsg t with
+        | .ok mo, .ok mt =>
+          if sent.getD (peer, o.compress) 0 == 0 then
+            delivery := .error s!"line {e.line}: party {e.party} received a tampered copy of a \
+              message that party {peer} did not send"
+          else if !tamperedCopy mo mt then
+            delivery := .error s!"line {e.line}: the tampered message differs from the original \
+              in more than the chunk bytes"
+          else
+            let kt := (peer, t.compress)
+            sent := sent.insert kt (sent.getD kt 0 + 1)
+        | _, _ => delivery := .error s!"line {e.line}: bad message in a tamper event"
+      | _, _ => delivery := .error s!"line {e.line}: a tamper event needs two messages"
     else if (e.f == "mlkem.generate" || e.f == "mlkem.encaps1") && randomness.isOk then
       let i := if e.f == "mlkem.generate" then 0 else 1
       if let some r := e.args[i]? then
diff --git a/src/monitor.rs b/src/monitor.rs
index dae409e..e09a056 100644
--- a/src/monitor.rs
+++ b/src/monitor.rs
@@ -7,8 +7,10 @@
 //! number, the party (`A` or `B`), the operation number, the function name, its arguments and
 //! its result, with bytes as lowercase hex. Operation 0 is a party's initialization; the test
 //! harness starts operation `n + 1` before each `States::send` or `States::recv` call
-//! (`begin_op`), and the call's step event ends it. The log is written only when the environment variable `SPQR_MONITOR_DIR`
-//! names a directory and the current thread has a party set (`set_party`). The file is
+//! (`begin_op`), and the call's step event ends it. A test that tampers with a message in
+//! transit writes a `tamper` event in the operation of the `recv` that receives the tampered
+//! message. The log is written only when the environment variable `SPQR_MONITOR_DIR` names a
+//! directory and the current thread has a party set (`set_party`). The file is
 //! `$SPQR_MONITOR_DIR/<thread name>.jsonl`. The Lean program `spqr-monitor` checks the log
 //! against `BraidModel`.
 
@@ -112,14 +114,28 @@ pub fn set_party(is_a: bool) {
     SINK.with(|s| s.borrow_mut().party = Some(if is_a { 'A' } else { 'B' }));
 }
 
+/// Run `f` with no events written: for a dry run of a call that is not part of the trace.
+#[cfg(test)]
+pub fn paused<T>(f: impl FnOnce() -> T) -> T {
+    let party = SINK.with(|s| s.borrow_mut().party.take());
+    let r = f();
+    SINK.with(|s| s.borrow_mut().party = party);
+    r
+}
+
 fn emit(f: &str, args: &str, ret: &str) {
+    emit_at(0, f, args, ret)
+}
+
+/// Write an event in operation `op + offset`, where `op` is the current operation.
+fn emit_at(offset: u64, f: &str, args: &str, ret: &str) {
     SINK.with(|s| {
         let mut s = s.borrow_mut();
         let Some(p) = s.party else { return };
         if !s.open() {
             return;
         }
-        let (session, op) = (s.session, s.op);
+        let (session, op) = (s.session, s.op + offset);
         let out = s.out.as_mut().expect("opened above");
         writeln!(
             out,
@@ -320,3 +336,15 @@ pub fn recv_step(pre: (&'static str, u64), msg: &Message, r: &Result<Recv, Error
         &ret,
     );
 }
+
+#[cfg(test)]
+/// The network replaced the message `orig` of the peer by `tampered`, which the current party
+/// receives next. The event belongs to the operation of that `recv`, the next operation.
+pub fn tamper(orig: &Message, tampered: &Message) {
+    emit_at(
+        1,
+        "tamper",
+        &format!("[{},{}]", message(orig), message(tampered)),
+        "null",
+    );
+}
diff --git a/src/test/messaging_scka.rs b/src/test/messaging_scka.rs
index 4d9404b..20ac59c 100644
--- a/src/test/messaging_scka.rs
+++ b/src/test/messaging_scka.rs
@@ -49,6 +49,14 @@ pub struct GenericMessagingScka<SCKA: Scka> {
     last_emitted_epoch: Epoch,
 }
 
+#[cfg(feature = "monitor")]
+impl<SCKA: Scka> GenericMessagingScka<SCKA> {
+    /// The state of the underlying SCKA.
+    pub fn scka(&self) -> &SCKA {
+        &self.scka
+    }
+}
+
 impl<SCKA: Scka + SckaInitializer + Clone> MessagingScka for GenericMessagingScka<SCKA> {
     type CkaOutput = Secret;
 
diff --git a/src/test/orchestrator.rs b/src/test/orchestrator.rs
index ff1b29a..d8c2d98 100644
--- a/src/test/orchestrator.rs
+++ b/src/test/orchestrator.rs
@@ -15,6 +15,9 @@
 use crate::Error;
 
 use super::basic_messaging_behavior::BasicMessagingBehavior;
+
+#[cfg(feature = "monitor")]
+pub mod tamper;
 use super::messaging_behavior::MessagingBehavior;
 
 pub struct OrchestratorBase<K>
diff --git a/src/test/orchestrator/tamper.rs b/src/test/orchestrator/tamper.rs
new file mode 100644
index 0000000..2422378
--- /dev/null
+++ b/src/test/orchestrator/tamper.rs
@@ -0,0 +1,279 @@
+// Copyright 2026 The Beneficial AI Foundation
+// SPDX-License-Identifier: AGPL-3.0-only
+
+//! Test drivers that tamper with `Hdr` and `Ct2` chunks in transit, for the runtime monitor
+//! (feature `monitor`).
+//!
+//! Honest runs never deliver a bad MAC, so a monitor of honest traces cannot see a MAC check
+//! whose result the code ignores. These drivers deliver tampered chunks and log each one with a
+//! `tamper` event (`crate::monitor::tamper`). A `recv` that fails leaves the party in its old
+//! state (`GenericMessagingScka::messaging_scka_recv` keeps the old state on an error), and the
+//! run goes on.
+//!
+//! - `tamper_chaos` tampers with chunks that complete a decoder, so that the honest code fails
+//!   at the MAC check of that `recv`, and then delivers the original chunk.
+//! - `tamper_early` tampers with a chunk that does not complete the decoder. The honest code
+//!   accepts it and keeps it in the decoder, and every later decode of that epoch fails at the
+//!   MAC check: the party stays in that epoch for the rest of the session.
+//!
+//! Whether a chunk completes the decoder comes from a dry run on a clone of the receiver's
+//! state with the honest chunk and no events written. The dry run does not depend on the MAC
+//! check of a tampered chunk.
+
+use rand::prelude::*;
+use rand::rngs::OsRng;
+use rand_core::CryptoRng;
+
+use super::OrchestratorBase;
+use crate::encoding::Chunk;
+use crate::test::messaging_scka::{GenericMessagingScka, MessagingCkaVulnerability, MessagingScka};
+use crate::v1::chunked::states::{Message, MessagePayload, States};
+use crate::Error;
+
+type Cka = GenericMessagingScka<States>;
+
+/// A copy of `m`.
+fn copy_msg(m: &Message) -> Message {
+    let payload = match &m.payload {
+        MessagePayload::None => MessagePayload::None,
+        MessagePayload::Hdr(c) => MessagePayload::Hdr(*c),
+        MessagePayload::Ek(c) => MessagePayload::Ek(*c),
+        MessagePayload::EkCt1Ack(c) => MessagePayload::EkCt1Ack(*c),
+        MessagePayload::Ct1Ack(b) => MessagePayload::Ct1Ack(*b),
+        MessagePayload::Ct1(c) => MessagePayload::Ct1(*c),
+        MessagePayload::Ct2(c) => MessagePayload::Ct2(*c),
+    };
+    Message {
+        epoch: m.epoch,
+        payload,
+    }
+}
+
+/// The kinds of chunk that the drivers tamper with.
+#[derive(Clone, Copy, PartialEq, Debug)]
+enum Kind {
+    Hdr,
+    Ct2,
+}
+
+/// The kind of a `Hdr` or `Ct2` message.
+fn kind(m: &Message) -> Option<Kind> {
+    match &m.payload {
+        MessagePayload::Hdr(_) => Some(Kind::Hdr),
+        MessagePayload::Ct2(_) => Some(Kind::Ct2),
+        _ => None,
+    }
+}
+
+/// A copy of the `Hdr` or `Ct2` message `m` with one random byte of the chunk changed.
+fn tampered<R: CryptoRng>(m: &Message, rng: &mut R) -> Message {
+    let mut t = copy_msg(m);
+    let c: &mut Chunk = match &mut t.payload {
+        MessagePayload::Hdr(c) | MessagePayload::Ct2(c) => c,
+        _ => unreachable!("only Hdr and Ct2 chunks are tampered with"),
+    };
+    let i = rng.next_u32() as usize % c.data.len();
+    c.data[i] ^= rng.random_range(1..=255u8);
+    t
+}
+
+/// Whether `state` adds the chunk of `m` to its decoder: a `Hdr` chunk in `NoHeaderReceived`
+/// or a `Ct2` chunk in `EkSentCt1Received`, of the state's epoch. Other states that accept these
+/// chunks start a new decoder or ignore them.
+fn decodes(state: &States, m: &Message) -> bool {
+    matches!(
+        (crate::monitor::state_info(state), kind(m)),
+        (("NoHeaderReceived", ep), Some(Kind::Hdr))
+            | (("EkSentCt1Received", ep), Some(Kind::Ct2)) if ep == m.epoch
+    )
+}
+
+/// The result of a dry run of `recv` of `m` from `state`, with no events written: `None` when
+/// the `recv` fails, `Some(true)` when it changes the state's name or epoch, `Some(false)`
+/// otherwise.
+fn dry_run(state: &States, m: &Message) -> Option<bool> {
+    let pre = crate::monitor::state_info(state);
+    let r = crate::monitor::paused(|| state.clone().recv(m));
+    r.ok().map(|r| crate::monitor::state_info(&r.state) != pre)
+}
+
+/// Counts of tampered deliveries.
+#[derive(Default, Debug)]
+struct Stats {
+    /// The code returned an error.
+    rejected: usize,
+    /// The code accepted the tampered chunk.
+    accepted: usize,
+}
+
+impl OrchestratorBase<Cka> {
+    fn agent(&self, is_alex: bool) -> &Cka {
+        if is_alex {
+            &self.alex
+        } else {
+            &self.blake
+        }
+    }
+
+    /// Receive `msg`, which is not taken from the queue, and record the key it outputs.
+    fn deliver(&mut self, is_alex: bool, msg: &Message) -> Result<(), Error> {
+        crate::monitor::set_party(is_alex);
+        let emitted_ep = {
+            let (agent, _iq, _oq, key_history) = self.data_for_agent(is_alex);
+            let mut rng = OsRng;
+            let out = agent.messaging_scka_recv(msg, &mut rng)?;
+            out.map(|(_ep, key)| {
+                key_history.push(key);
+                agent.last_emitted_epoch()
+            })
+        };
+        if let Some(ep) = emitted_ep {
+            if is_alex {
+                self.last_emitted_epoch_a = ep;
+            } else {
+                self.last_emitted_epoch_b = ep;
+            }
+        }
+        Ok(())
+    }
+
+    /// Log a tampered copy `t` of `orig` and deliver it. Return whether the code accepted it.
+    fn deliver_tampered(&mut self, is_alex: bool, orig: &Message, t: &Message) -> bool {
+        crate::monitor::set_party(is_alex);
+        crate::monitor::tamper(orig, t);
+        self.deliver(is_alex, t).is_ok()
+    }
+
+    /// Receive the `i`-th message of the queue. With probability `prob`, when it is a `Hdr` or
+    /// `Ct2` chunk that completes the decoder of the state (`decodes` and the dry run changes
+    /// the state), first deliver a tampered copy. If the code
+    /// rejects the copy, deliver the original; if it accepts the copy, drop the original.
+    fn receive_at_tampering<R: CryptoRng>(
+        &mut self,
+        is_alex: bool,
+        i: usize,
+        prob: f64,
+        stats: &mut Stats,
+        rng: &mut R,
+    ) -> Result<(), Error> {
+        let incoming = if is_alex {
+            &self.b2a_msg_queue
+        } else {
+            &self.a2b_msg_queue
+        };
+        let msg = &incoming[i];
+        let state = self.agent(is_alex).scka();
+        if decodes(state, msg) && rng.random_bool(prob) && dry_run(state, msg) == Some(true) {
+            let orig = copy_msg(msg);
+            let t = tampered(&orig, rng);
+            if self.deliver_tampered(is_alex, &orig, &t) {
+                stats.accepted += 1;
+                self.drop_message_at(is_alex, i);
+                return Ok(());
+            }
+            stats.rejected += 1;
+        }
+        self.receive_at(is_alex, i).map(|_| ())
+    }
+}
+
+/// The `chaos` driver, where each delivery of a `Hdr` or `Ct2` chunk that completes the
+/// decoder is tampered with probability `prob`.
+pub fn tamper_chaos<R: CryptoRng>(num_ticks: usize, prob: f64, rng: &mut R) -> Result<(), Error> {
+    let ooo_prob = 0.7;
+    let send_limit = 10;
+    let drop_message_prob = 0.1;
+    let mut stats = Stats::default();
+    let mut orchestrator = OrchestratorBase::<Cka>::new(rng)?;
+    for i in 0..num_ticks {
+        let use_alex = if i % 100 < 50 {
+            rng.random_bool(0.25)
+        } else {
+            rng.random_bool(0.75)
+        };
+        if rng.random_bool(ooo_prob) {
+            let qlen = orchestrator.qlen(use_alex);
+            if qlen > 0 {
+                let at = rng.next_u32() as usize % qlen;
+                orchestrator.receive_at_tampering(use_alex, at, prob, &mut stats, rng)?;
+            }
+        }
+        let num_to_send = rng.next_u32() % send_limit;
+        for _ in 0..num_to_send {
+            orchestrator.send(use_alex, rng)?;
+            if rng.random_bool(drop_message_prob) {
+                orchestrator.drop_message_at(use_alex, 0);
+            }
+        }
+        loop {
+            let qlen = orchestrator.qlen(use_alex);
+            if qlen <= 20 {
+                break;
+            }
+            let at = rng.next_u32() as usize % qlen;
+            orchestrator.receive_at_tampering(use_alex, at, prob, &mut stats, rng)?;
+        }
+        orchestrator.key_history_is_consistent();
+    }
+    orchestrator.print_key_history_lengths();
+    println!("tampered chunks: {stats:?}");
+    assert!(stats.rejected > 0, "no tampered chunk was rejected");
+    Ok(())
+}
+
+/// Sessions of `num_ticks` ticks where one `Hdr` or `Ct2` chunk that does not complete the
+/// decoder is replaced by a tampered copy. In each tick one random party sends a message and the
+/// other party receives its whole queue in order. The party that received the tampered chunk
+/// (the victim) must fail at least once later, and the keys of both parties must agree.
+pub fn tamper_early<R: CryptoRng>(
+    sessions: usize,
+    num_ticks: usize,
+    rng: &mut R,
+) -> Result<(), Error> {
+    for s in 0..sessions {
+        let target = if s % 2 == 0 { Kind::Hdr } else { Kind::Ct2 };
+        let mut orchestrator = OrchestratorBase::<Cka>::new(rng)?;
+        let mut victim: Option<bool> = None;
+        let mut victim_errors = 0usize;
+        for _ in 0..num_ticks {
+            let sender = rng.random_bool(0.5);
+            orchestrator.send(sender, rng)?;
+            let is_alex = !sender;
+            while orchestrator.qlen(is_alex) > 0 {
+                let incoming = if is_alex {
+                    &mut orchestrator.b2a_msg_queue
+                } else {
+                    &mut orchestrator.a2b_msg_queue
+                };
+                let msg = incoming.pop_front().expect("queue is not empty");
+                let state = orchestrator.agent(is_alex).scka();
+                if victim.is_none()
+                    && kind(&msg) == Some(target)
+                    && decodes(state, &msg)
+                    && dry_run(state, &msg) == Some(false)
+                {
+                    let t = tampered(&msg, rng);
+                    assert!(
+                        orchestrator.deliver_tampered(is_alex, &msg, &t),
+                        "a tampered chunk that does not complete the decoder was rejected"
+                    );
+                    victim = Some(is_alex);
+                    continue;
+                }
+                match orchestrator.deliver(is_alex, &msg) {
+                    Ok(()) => {}
+                    Err(_) if victim == Some(is_alex) => victim_errors += 1,
+                    Err(e) => return Err(e),
+                }
+            }
+            orchestrator.key_history_is_consistent();
+        }
+        println!("session {s}: tampered {target:?} chunk, victim errors {victim_errors}");
+        assert!(
+            victim.is_some(),
+            "session {s}: no {target:?} chunk was tampered"
+        );
+        assert!(victim_errors > 0, "session {s}: the victim never failed");
+    }
+    Ok(())
+}
diff --git a/src/v1.rs b/src/v1.rs
index c1a6825..7c19ad6 100644
--- a/src/v1.rs
+++ b/src/v1.rs
@@ -30,6 +30,20 @@ fn random_balanced() -> Result<(), Error> {
         orchestrator::random_balanced::<Cka, _>(&mut rng)
     }
 
+    #[cfg(feature = "monitor")]
+    #[test]
+    fn tamper_chaos() -> Result<(), Error> {
+        let mut rng = OsRng.unwrap_err();
+        orchestrator::tamper::tamper_chaos(10000, 0.3, &mut rng)
+    }
+
+    #[cfg(feature = "monitor")]
+    #[test]
+    fn tamper_early() -> Result<(), Error> {
+        let mut rng = OsRng.unwrap_err();
+        orchestrator::tamper::tamper_early(6, 300, &mut rng)
+    }
+
     #[test]
     fn chaos() -> Result<(), Error> {
         type Scka = states::States;
```
