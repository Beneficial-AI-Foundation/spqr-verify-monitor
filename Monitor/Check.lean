/-
Copyright (c) 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Lacramioara Astefanoaei
-/
import Monitor.Trace

/-! # Checking one session

For each party of a session the monitor:

1. splits the party's events into operations (`op`): operation 0 is the initialization, every
   other operation ends with exactly one step event;
2. builds one table per operation from that operation's primitive calls, and adds the decoder
   result and parity chunk of the operation, read at the model state before it (the learning
   pass, not trusted);
3. runs the verified checker `BraidModel.checkRun` from `initAliceO` / `initBobO` over the
   pairs (table, observation). Its result is the verdict; `BraidModel.accepted_alice` and
   `BraidModel.accepted_bob` state what an acceptance means.

It also checks that each table entry is a function across the party's operations, and, for the
session, the delivery of messages, the agreement of keys and the reuse of randomness (not
covered by the theorems). -/

open Lean Std Aeneas Aeneas.Std BraidModel

namespace Monitor

/-- One operation of one party: its number, its events, and its step event (none for the
initialization). -/
structure Operation where
  op : Nat
  events : Array Event
  step : Option Event
  deriving Inhabited

/-- The result of checking one party. -/
structure PartyResult where
  party : String
  operations : Nat
  verdict : Except String Unit
  /-- Secrets by epoch from the accepted observations. -/
  keys : List Key

/-- Group a party's events into operations and check their shape. -/
def operations (evs : Array Event) : Except String (Array Operation) := do
  let mut ops : Array Operation := #[]
  let mut cur : Option Operation := none
  for e in evs do
    match cur with
    | some o =>
      if o.op == e.op then
        if o.step.isSome then
          throw s!"line {e.line}: event after the step event of operation {o.op}"
        let step := if e.isStep then some e else none
        cur := some ⟨o.op, o.events.push e, step⟩
      else
        if e.op < o.op then throw s!"line {e.line}: operation {e.op} after operation {o.op}"
        if o.op != 0 && o.step.isNone then
          throw s!"operation {o.op} has no step event"
        ops := ops.push o
        cur := some ⟨e.op, #[e], if e.isStep then some e else none⟩
    | none =>
      if e.op != 0 then throw s!"line {e.line}: the first operation is {e.op}, not 0"
      cur := some ⟨e.op, #[e], if e.isStep then some e else none⟩
  match cur with
  | some o =>
    if o.op != 0 && o.step.isNone then throw s!"operation {o.op} has no step event"
    ops := ops.push o
  | none => pure ()
  return ops

/-- Insert into a table; a different value for a known key is an error. -/
def insertFn {α β : Type} [BEq α] [Hashable α] [BEq β] (what : String) (m : HashMap α β)
    (k : α) (v : β) : Except String (HashMap α β) :=
  match m[k]? with
  | some v' =>
    if v' == v then .ok m else .error s!"{what} returned two different values for one argument"
  | none => .ok (m.insert k v)

/-- Add one primitive call to a table. Events that are not primitive calls are skipped. -/
def addCall (T : Tables) (e : Event) : Except String Tables := do
  let a := e.args
  match e.f with
  | "hkdf" =>
    let k := (← jBytes (← arg a 0), ← jBytes (← arg a 1), ← jBytes (← arg a 2), ← jNat (← arg a 3))
    let m ← insertFn "hkdf" T.hkdf k (← jBytes e.ret)
    return { T with hkdf := m }
  | "hmac" =>
    let k := (← jBytes (← arg a 0), ← jBytes (← arg a 1))
    let m ← insertFn "hmac" T.hmac k (← jBytes e.ret)
    return { T with hmac := m }
  | "mlkem.generate" =>
    let r ← match e.ret with | .arr r => pure r | _ => throw "generate: bad result"
    let v := (← jBytes (← arg r 0), ← jBytes (← arg r 1), ← jBytes (← arg r 2))
    let m ← insertFn "generate" T.keyGen (← jBytes (← arg a 0)) v
    return { T with keyGen := m }
  | "mlkem.encaps1" =>
    let r ← match e.ret with | .arr r => pure r | _ => throw "encaps1: bad result"
    let v := (← jBytes (← arg r 0), ← jBytes (← arg r 1), ← jBytes (← arg r 2))
    let k := (← jBytes (← arg a 0), ← jBytes (← arg a 1))
    let m ← insertFn "encaps1" T.encaps1 k v
    return { T with encaps1 := m }
  | "mlkem.encaps2" =>
    -- logged as `[ek, es]`, keyed as `(es, ek)` like the model's `Encaps2`
    let k := (← jBytes (← arg a 1), ← jBytes (← arg a 0))
    let m ← insertFn "encaps2" T.encaps2 k (← jBytes e.ret)
    return { T with encaps2 := m }
  | "mlkem.decaps" =>
    let k := (← jBytes (← arg a 0), ← jBytes (← arg a 1), ← jBytes (← arg a 2))
    let m ← insertFn "decaps" T.decaps k (← jBytes e.ret)
    return { T with decaps := m }
  | "mlkem.ek_matches_header" =>
    -- logged as `[ek, hdr]`, keyed as `(hdr, ek)` like the model's `ekMatches`
    let k := (← jBytes (← arg a 1), ← jBytes (← arg a 0))
    let m ← insertFn "ek_matches_header" T.ekMatches k (← e.ret.getBool?)
    return { T with ekMatches := m }
  | _ => return T

/-- Add a decoder result to a table. -/
def addMessage (T : Tables) (d : MDec) (m : Option Bytes) : Except String Tables := do
  let t ← insertFn "decoder" T.message d m
  return { T with message := t }

/-- Add a parity chunk to a table. -/
def addParity (T : Tables) (enc : MEnc) (c : MChunk) : Except String Tables := do
  let t ← insertFn "encoder" T.parity enc c
  return { T with parity := t }

/-- The decoder that `receiveEq` adds the chunk of `m` to in state `σ`, with the chunk added. -/
def decoderAfter (σ : State MEnc MDec) (m : Msg MChunk) : Option MDec :=
  if m.epoch != σ.epoch then none else
  let add (d : MDec) (c : MChunk) : MDec := (d.1, d.2 ++ [c])
  match σ, m.payload with
  | .headerSent _ _ _ d _, .ct1 c => some (add d c)
  | .ekSentCt1Received _ _ _ _ d, .ct2 c => some (add d c)
  | .noHeaderReceived _ _ d, .hdr c => some (add d c)
  | .ct1Sampled _ _ _ _ _ _ d, .ek c => some (add d c)
  | .ct1Sampled _ _ _ _ _ _ d, .ekCt1Ack c => some (add d c)
  | .ct1Acknowledged _ _ _ _ _ d, .ek c => some (add d c)
  | .ct1Acknowledged _ _ _ _ _ d, .ekCt1Ack c => some (add d c)
  | _, _ => none

/-- The encoder that `send` takes the next chunk from in state `σ`. Fresh encoders (transitions
(1) and (7)) start with a systematic chunk and need no entry. -/
def encoderOf : State MEnc MDec → Option MEnc
  | .keysSampled _ _ _ _ _ enc | .headerSent _ _ _ _ enc | .ct1Received _ _ _ _ enc
  | .ct1Sampled _ _ _ _ _ enc _ | .ekReceivedCt1Sampled _ _ _ _ _ _ enc
  | .ct2Sampled _ _ enc => some enc
  | _ => none

/-- The message of an observation. -/
def obsMsg : Obs MChunk → Msg MChunk
  | .send _ m .. | .recvOk m .. | .recvErr m => m

/-- A short description of a state. -/
def State.describe (σ : State MEnc MDec) : String := s!"{repr σ.label} epoch {σ.epoch}"

/-- A short description of a message. -/
def describeMsg (m : Msg MChunk) : String :=
  let p := match m.payload with
    | .none => "none" | .ct1Ack => "ct1ack"
    | .hdr c => s!"hdr #{c.index}" | .ek c => s!"ek #{c.index}"
    | .ekCt1Ack c => s!"ekct1ack #{c.index}" | .ct1 c => s!"ct1 #{c.index}"
    | .ct2 c => s!"ct2 #{c.index}"
  s!"epoch {m.epoch} {p}"

/-- Which primitive value of a step is missing, for the report. It follows `sendO` and
`receiveEqO` for the transitions that use primitives. -/
def explainMissing (Q : OPrims MEnc MDec MChunk) (σ : State MEnc MDec) : Obs MChunk → String
  | .send r _ _ _ _ =>
    match σ with
    | .keysUnsampled e a =>
      match Q.keyGen r with
      | none => "no generate call for the randomness"
      | some kg => match Auth.macHdrO Q a e kg.2.1 with
        | none => "no hmac call with the key and data of the header MAC"
        | some _ => "no chunk of the header encoder"
    | .headerReceived e a hdr _ =>
      match Q.encaps1 hdr r with
      | none => "no encaps1 call for the header and randomness"
      | some x => match Q.kdfOk x.2.2 e with
        | none => "no hkdf call for KDF_OK"
        | some ss => match Auth.updateO Q a e ss with
          | none => "no hkdf call for KDF_AUTH"
          | some _ => "no chunk of the ct1 encoder"
    | _ => "no parity chunk for the encoder"
  | .recvOk m .. | .recvErr m =>
    match decoderAfter σ m with
    | none => "a primitive value of a payload without a decoder (ct2 encoder)"
    | some d =>
      match Q.message d with
      | none => "no decoder.message call for the decoder"
      | some none => "unknown"
      | some (some msg) =>
        match σ with
        | .ekSentCt1Received e a dk ct1 _ =>
          match Q.decaps dk ct1 (msg.take Q.ct2Size) with
          | none => "no decaps call"
          | some ss₀ => match Q.kdfOk ss₀ e with
            | none => "no hkdf call for KDF_OK"
            | some ss => match Auth.updateO Q a e ss with
              | none => "no hkdf call for KDF_AUTH"
              | some a' => match Auth.macCtO Q a' e (ct1 ++ msg.take Q.ct2Size) with
                | none => "no hmac call with the key and data of the ciphertext MAC (verify_ct)"
                | some _ => "unknown"
        | .noHeaderReceived e a _ =>
          match Auth.macHdrO Q a e (msg.take Q.headerSize) with
          | none => "no hmac call with the key and data of the header MAC (verify_hdr)"
          | some _ => "unknown"
        | .ct1Sampled _ _ hdr .. | .ct1Acknowledged _ _ hdr .. =>
          match Q.ekMatches hdr msg with
          | none => "no ek_matches_header call"
          | some _ => "no encaps2 call, or no hmac call with the key and data of the ciphertext \
          MAC, for the ct2 encoder"
        | _ => "unknown"

/-- Why `checkStep Q σ o` fails, for the report. -/
def explainStep (Q : OPrims MEnc MDec MChunk) (σ : State MEnc MDec) (o : Obs MChunk) : String :=
  match o with
  | .send r m k l e =>
    match sendO Q σ r with
    | none => s!"missing primitive value: {explainMissing Q σ o}"
    | some (σ', m', k') =>
      let d := [if m'.epoch != m.epoch then some "message epoch" else none,
        if m'.payload.ctorIdx != m.payload.ctorIdx then some "payload kind" else none,
        if m' != m && m'.epoch == m.epoch && m'.payload.ctorIdx == m.payload.ctorIdx
          then some "chunk bytes" else none,
        if k'.map (·.1) != k.map (·.1) then some "key epoch" else none,
        if k' != k && k'.map (·.1) == k.map (·.1) then some "key bytes" else none,
        if σ'.label != l then some s!"state (model {repr σ'.label}, code {repr l})" else none,
        if σ'.epoch != e then some s!"epoch (model {σ'.epoch}, code {e})" else none]
      s!"send differs from the model in: {", ".intercalate d.reduceOption}"
  | .recvOk m k l e =>
    match receiveO Q σ m with
    | none => s!"missing primitive value: {explainMissing Q σ o}"
    | some none => "the model's Receive() fails, the code accepted"
    | some (some (σ', k')) =>
      let d := [
        if k'.map (·.1) != k.map (·.1) then some "key epoch" else none,
        if k' != k && k'.map (·.1) == k.map (·.1) then some "key bytes" else none,
        if σ'.label != l then some s!"state (model {repr σ'.label}, code {repr l})" else none,
        if σ'.epoch != e then some s!"epoch (model {σ'.epoch}, code {e})" else none]
      s!"recv differs from the model in: {", ".intercalate d.reduceOption}"
  | .recvErr _ =>
    match receiveO Q σ (obsMsg o) with
    | none => s!"missing primitive value: {explainMissing Q σ o}"
    | some (some _) => "the model's Receive() succeeds, the code returned an error"
    | some none => "unknown"

/-- The randomness of an operation: the seed of its `generate` call or the randomness of its
`encaps1` call, if any. -/
def randomness (o : Operation) : Except String Bytes := do
  let rs ← o.events.filterMapM fun e =>
    match e.f with
    | "mlkem.generate" => do return some (← jBytes (← arg e.args 0))
    | "mlkem.encaps1" => do return some (← jBytes (← arg e.args 1))
    | _ => return none
  match rs.toList with
  | [] => return []
  | [r] => return r
  | _ => throw s!"operation {o.op} drew randomness twice"

/-- The single `decoder.message` result of an operation, if any. -/
def decoded (o : Operation) : Except String (Option (Nat × Option Bytes)) := do
  let rs ← o.events.filterMapM fun e =>
    if e.f == "decoder.message" then do
      let m ← if e.ret.isNull then pure none else some <$> jBytes e.ret
      return some (← jNat (← arg e.args 0), m)
    else return none
  match rs.toList with
  | [] => return none
  | [r] => return some r
  | _ => throw s!"operation {o.op} has two decoder.message events"

/-- Check one party of a session. -/
def checkParty (party : String) (evs : Array Event) : PartyResult := Id.run do
  let fail (msg : String) (n : Nat) : PartyResult := ⟨party, n, .error msg, []⟩
  let ops ← match operations evs with
    | .ok ops => pure ops
    | .error err => return fail err 0
  let some init := ops[0]? | return fail "no initialization" 0
  if init.op != 0 then return fail "no initialization (operation 0)" 0
  if let some e := init.events.find? (·.isStep) then
    return fail s!"line {e.line}: step event in the initialization (operation 0)" 0
  let some ie := init.events.find? (·.f == "init") | return fail "no init event" 0
  if (init.events.filter (·.f == "init")).size != 1 then
    return fail "two init events in the initialization" 0
  let role ← match (arg ie.args 0).bind Json.getStr? with
    | .ok r => pure r
    | .error err => return fail err 0
  let expected := if party == "A" then "a" else "b"
  if role != expected then
    return fail s!"line {ie.line}: party {party} initializes with role {role}, not {expected}" 0
  let ss ← match (arg ie.args 1).bind jBytes with
    | .ok s => pure s
    | .error err => return fail err 0
  -- `all` collects every entry of the party, to check that each primitive is a function.
  let mut all : Tables := {}
  let mut T0 : Tables := {}
  for e in init.events do
    match addCall T0 e, addCall all e with
    | .ok t, .ok a => T0 := t; all := a
    | .error err, _ | _, .error err => return fail err 0
  let Q0 := T0.prims
  let σ0? := if party == "A" then initAliceO Q0 ss else initBobO Q0 ss
  let some σ0 := σ0? | return fail "initialization: no hkdf call for the authenticator" 0
  -- learning pass: one table per operation, replayed with the checker's own step function
  let mut steps : Array (OPrims MEnc MDec MChunk × Obs MChunk) := #[]
  let mut σ? : Option (State MEnc MDec) := some σ0
  let mut firstFail : Option String := none
  for o in ops[1:] do
    let some se := o.step | return fail s!"operation {o.op} has no step event" steps.size
    let r ← match randomness o with
      | .ok r => pure r
      | .error err => return fail err steps.size
    let obs ← match parseObs se r with
      | .ok obs => pure obs
      | .error err => return fail s!"line {se.line}: {err}" steps.size
    let mut T : Tables := {}
    for e in o.events do
      match addCall T e, addCall all e with
      | .ok t, .ok a => T := t; all := a
      | .error err, _ | _, .error err => return fail s!"line {e.line}: {err}" steps.size
    if let some σ := σ? then
      -- the state before the call, as the code logged it, is the model's state
      let pre : Except String (Label × Nat) := do
        return (← parseLabel (← (← arg se.args 0).getStr?), ← jNat (← arg se.args 1))
      match pre with
      | .error err => return fail s!"line {se.line}: {err}" steps.size
      | .ok (l, ep) =>
        if l != σ.label || ep != σ.epoch then
          return fail s!"operation {o.op} (line {se.line}): the code's state before the call is \
            {repr l} epoch {ep}, the model's is {State.describe σ}" steps.size
      -- the decoder result of a receive, at the decoder the model adds the chunk to
      match obs, decoded o with
      | .recvOk m .. , .ok (some (pts, res)) | .recvErr m, .ok (some (pts, res)) =>
        if let some d := decoderAfter σ m then
          if d.1 != 2 * pts then
            return fail s!"operation {o.op}: decoder of {d.1} bytes, code needs {pts} points"
              steps.size
          match addMessage T d res, addMessage all d res with
          | .ok t, .ok a => T := t; all := a
          | .error err, _ | _, .error err => return fail s!"operation {o.op}: {err}" steps.size
      | _, .error err => return fail err steps.size
      | _, _ => pure ()
      -- the parity chunk of a send
      match obs, encoderOf σ with
      | .send _ m .., some enc =>
        if enc.2 ≥ enc.1.length / 32 then
          let c? : Option MChunk := match m.payload with
            | .hdr c | .ek c | .ekCt1Ack c | .ct1 c | .ct2 c => some c
            | _ => none
          if let some c := c? then
            if c.index != enc.2 % 65536 || c.data.length != 32 then
              return fail s!"operation {o.op}: parity chunk #{c.index} of {c.data.length} bytes, \
                expected index {enc.2 % 65536} and 32 bytes" steps.size
            match addParity T enc c, addParity all enc c with
            | .ok t, .ok a => T := t; all := a
            | .error err, _ | _, .error err => return fail s!"operation {o.op}: {err}" steps.size
      | _, _ => pure ()
      let Q := T.prims
      match checkStep Q σ obs with
      | some σ' => σ? := some σ'
      | none =>
        let why := explainStep Q σ obs
        let other := if (why.splitOn "hmac").length > 1 && T.hmac.size > 0 then
            s!" (this operation logged {T.hmac.size} hmac call(s), on other keys or data)"
          else ""
        firstFail := some s!"operation {o.op} (line {se.line}), {se.f} in {State.describe σ}, \
          message {describeMsg (obsMsg obs)}: {why}{other}"
        σ? := none
    steps := steps.push (T.prims, obs)
  -- the verdict of the verified checker
  match checkRun σ0 steps.toList with
  | some _ =>
    if let some f := firstFail then
      return fail s!"internal: the learning pass failed but checkRun accepts: {f}" steps.size
    ⟨party, steps.size, .ok (), obsKeys (steps.toList.map (·.2))⟩
  | none =>
    fail (firstFail.getD "rejected (no diagnosis)") steps.size

/-- The result of the session-level checks. -/
structure SessionChecks where
  delivery : Except String Unit
  keys : Except String Unit
  incompleteEpochs : List Nat
  randomness : Except String Unit

/-- Delivery, key agreement and reuse of randomness for a session's events, in file order. -/
def sessionChecks (evs : Array Event) (ka kb : List Key) : SessionChecks := Id.run do
  -- delivery: each receive consumes an equal earlier send of the other party
  let mut sent : HashMap (String × String) Nat := {}
  let mut delivery : Except String Unit := .ok ()
  let mut seen : HashSet String := {}
  let mut randomness : Except String Unit := .ok ()
  for e in evs do
    if e.f == "States::send" then
      if let .ok m := e.ret.getObjVal? "msg" then
        let k := (e.party, m.compress)
        sent := sent.insert k (sent.getD k 0 + 1)
    else if e.f == "States::recv" && delivery.isOk then
      if let some m := e.args[2]? then
        let peer := if e.party == "A" then "B" else "A"
        let k := (peer, m.compress)
        match sent[k]? with
        | some (n + 1) => sent := sent.insert k n
        | _ => delivery := .error s!"line {e.line}: party {e.party} received a message that \
            party {peer} did not send"
    else if (e.f == "mlkem.generate" || e.f == "mlkem.encaps1") && randomness.isOk then
      let i := if e.f == "mlkem.generate" then 0 else 1
      if let some r := e.args[i]? then
        let s := r.compress
        if seen.contains s then
          randomness := .error s!"line {e.line}: {e.f} reuses randomness of an earlier call"
        seen := seen.insert s
  -- keys: at most one per epoch and party, equal where both parties have one
  let toMap (ks : List Key) : Except String (HashMap Nat Bytes) :=
    ks.foldlM (init := {}) fun m (ep, s) =>
      if m.contains ep then .error s!"two keys for epoch {ep}" else .ok (m.insert ep s)
  let keys : Except String Unit × List Nat := match toMap ka, toMap kb with
    | .error err, _ => (.error s!"party A: {err}", [])
    | _, .error err => (.error s!"party B: {err}", [])
    | .ok ma, .ok mb =>
      let eps := (ma.keys ++ mb.keys).eraseDups.mergeSort
      eps.foldl (init := (.ok (), [])) fun (r, inc) ep =>
        match ma[ep]?, mb[ep]? with
        | some a, some b => if a == b || !r.isOk then (r, inc)
          else (.error s!"epoch {ep}: the parties' secrets differ", inc)
        | _, _ => (r, inc ++ [ep])
  ⟨delivery, keys.1, keys.2, randomness⟩

end Monitor
