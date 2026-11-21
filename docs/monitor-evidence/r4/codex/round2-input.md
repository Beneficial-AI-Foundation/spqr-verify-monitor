# Review round 2

Round 1 (you) found: HIGH synthetic copies could authorize further tampering and manufacture duplicate deliveries (Monitor/Check.lean sessionChecks); MEDIUM a tamper event was not bound to the receive of its operation. The new commit below fixes both. It was tested on five forged traces: original not sent, copy with another index, your duplicate-credit trace tamper(m,t)+tamper(t,m), your trace where the tamper operation receives the original and the next operation the copy, and two tamper events in one operation; all fail delivery. Honest traces still pass; R4 traces still rejected.

Check that the fix is correct and complete, and look for anything still wrong in the whole change (git diff f56fb87..HEAD, Rust and Lean). Concrete issues only, cite file:line, prioritized HIGH/MEDIUM/LOW. Zero findings is a valid answer.

```diff
commit b629a74021ade865cad85af61355d1e7377b2d6a
Author: astefano <lacramioara.astefanoaei@gmail.com>
Date:   Thu Nov 19 21:30:56 2026 +0100

    Tie each tamper event to the receive of its operation
    
    A tampered copy no longer counts as a send. A tamper event allows one
    receive of the copy, in its own operation, and its original must be a
    send of the peer. Before, a copy could serve as the original of a later
    tamper event and give a second delivery of a sent message, and a tamper
    event could allow a receive in another operation.
    
    Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

diff --git a/Monitor/Check.lean b/Monitor/Check.lean
index 98df29f..d0f2111 100644
--- a/Monitor/Check.lean
+++ b/Monitor/Check.lean
@@ -404,16 +404,25 @@ def tamperedCopy (m t : Msg MChunk) : Bool :=
 
 Delivery: each receive consumes an equal earlier send of the other party. A `tamper` event of a
 party, with arguments `[orig, copy]`, says that the network made `copy` from `orig` and that the
-party receives `copy` next. `orig` must be an earlier send of the other party that no receive
-consumed, and `copy` a tampered copy of it (`tamperedCopy`). Then `copy` counts as one more send
-of the other party. `orig` stays available. -/
+party receives `copy` in the same operation. `orig` must be an earlier send of the other party
+that no receive consumed (a send, not a tampered copy), and `copy` a tampered copy of it
+(`tamperedCopy`). The operation must have one tamper event, and its receive must be of `copy`.
+That receive consumes no send: `orig` stays available. -/
 def sessionChecks (evs : Array Event) (ka kb : List Key) : SessionChecks := Id.run do
-  -- delivery: each receive consumes an equal earlier send of the other party
+  -- delivery: each receive consumes an equal earlier send of the other party, or the copy of the
+  -- tamper event of its own operation
   let mut sent : HashMap (String × String) Nat := {}
+  -- the tamper event waiting for its receive: line, party, operation, copy
+  let mut pending : Option (Nat × String × Nat × String) := none
   let mut delivery : Except String Unit := .ok ()
   let mut seen : HashSet String := {}
   let mut randomness : Except String Unit := .ok ()
   for e in evs do
+    if let some (l, p, op, _) := pending then
+      if delivery.isOk && (e.party != p || e.op != op) then
+        delivery := .error s!"line {l}: the operation of the tamper event does not receive the \
+          tampered copy"
+        pending := none
     if e.f == "States::send" then
       if let .ok m := e.ret.getObjVal? "msg" then
         let k := (e.party, m.compress)
@@ -421,26 +430,34 @@ def sessionChecks (evs : Array Event) (ka kb : List Key) : SessionChecks := Id.r
     else if e.f == "States::recv" && delivery.isOk then
       if let some m := e.args[2]? then
         let peer := if e.party == "A" then "B" else "A"
-        let k := (peer, m.compress)
-        match sent[k]? with
-        | some (n + 1) => sent := sent.insert k n
-        | _ => delivery := .error s!"line {e.line}: party {e.party} received a message that \
-            party {peer} did not send"
+        match pending with
+        | some (l, _, _, c) =>
+          if m.compress != c then
+            delivery := .error s!"line {e.line}: party {e.party} received another message than \
+              the tampered copy of the tamper event on line {l}"
+          pending := none
+        | none =>
+          let k := (peer, m.compress)
+          match sent[k]? with
+          | some (n + 1) => sent := sent.insert k n
+          | _ => delivery := .error s!"line {e.line}: party {e.party} received a message that \
+              party {peer} did not send"
     else if e.f == "tamper" && delivery.isOk then
       let peer := if e.party == "A" then "B" else "A"
       match e.args[0]?, e.args[1]? with
       | some o, some t =>
         match parseMsg o, parseMsg t with
         | .ok mo, .ok mt =>
-          if sent.getD (peer, o.compress) 0 == 0 then
+          if pending.isSome then
+            delivery := .error s!"line {e.line}: two tamper events in one operation"
+          else if sent.getD (peer, o.compress) 0 == 0 then
             delivery := .error s!"line {e.line}: party {e.party} received a tampered copy of a \
               message that party {peer} did not send"
           else if !tamperedCopy mo mt then
             delivery := .error s!"line {e.line}: the tampered message differs from the original \
               in more than the chunk bytes"
           else
-            let kt := (peer, t.compress)
-            sent := sent.insert kt (sent.getD kt 0 + 1)
+            pending := some (e.line, e.party, e.op, t.compress)
         | _, _ => delivery := .error s!"line {e.line}: bad message in a tamper event"
       | _, _ => delivery := .error s!"line {e.line}: a tamper event needs two messages"
     else if (e.f == "mlkem.generate" || e.f == "mlkem.encaps1") && randomness.isOk then
@@ -450,6 +467,10 @@ def sessionChecks (evs : Array Event) (ka kb : List Key) : SessionChecks := Id.r
         if seen.contains s then
           randomness := .error s!"line {e.line}: {e.f} reuses randomness of an earlier call"
         seen := seen.insert s
+  if let some (l, _, _, _) := pending then
+    if delivery.isOk then
+      delivery := .error s!"line {l}: the operation of the tamper event does not receive the \
+        tampered copy"
   -- keys: at most one per epoch and party, equal where both parties have one
   let toMap (ks : List Key) : Except String (HashMap Nat Bytes) :=
     ks.foldlM (init := {}) fun m (ep, s) =>
```
