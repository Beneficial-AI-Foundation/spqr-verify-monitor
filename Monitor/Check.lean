/-
Copyright (c) 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Lacramioara Astefanoaei
-/
import Monitor.Trace

/-! # Checking one session

For each party of a session the monitor:

1. splits the party's events into operations (`op`): operation 0 is the initialization, and
   every other operation ends with its only step event;
2. builds one table per operation from that operation's primitive calls. In a learning pass
   that replays the steps with `BraidModel.checkStep`, it checks that the state the code logged
   before each step is the model's, and adds to the table the decoder result and parity chunk
   of the step, read at the model's state. The theorems do not cover how the tables are built:
   that they represent the log, including the values that the learning pass adds, is trusted;
3. runs the verified checker `BraidModel.checkRun` from `initAliceM` / `initBobM` over the
   pairs (partial primitives of the table, observation). Its result is the verdict;
   `BraidModel.accepted_alice` and `BraidModel.accepted_bob` state what an acceptance means.

It also checks that each primitive gives one value per argument across all the party's
operations and, for the session, the delivery of messages, the agreement of keys and the reuse
of randomness (`sessionChecks`, not covered by the theorems). A `tamper` event (a test changed a
message in transit) is not a primitive call: the party check skips it, and the delivery check
reads it. -/

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
  /-- The keys of the observations (`obsKeys`) when the checker accepts, `[]` otherwise. -/
  keys : List Key

/-- Group a party's events into operations, up to the first error. The operations are numbered in
increasing order from 0, and every operation other than 0 ends with its only step event. The
second component is the first error, if any: the operations before it are returned. -/
def operations (evs : Array Event) : Array Operation × Option String := Id.run do
  let stepOf (e : Event) : Option Event := if e.isStep then some e else none
  let mut ops : Array Operation := #[]
  let mut cur : Option Operation := none
  for e in evs do
    match cur with
    | some o =>
      if o.op == e.op then
        if o.step.isSome then
          return (ops.push o,
            some s!"line {e.line}: event after the step event of operation {o.op}")
        cur := some ⟨o.op, o.events.push e, stepOf e⟩
      else
        if e.op < o.op then
          let done := if o.op == 0 || o.step.isSome then ops.push o else ops
          return (done, some s!"line {e.line}: operation {e.op} after operation {o.op}")
        if o.op != 0 && o.step.isNone then
          return (ops, some s!"operation {o.op} has no step event")
        ops := ops.push o
        cur := some ⟨e.op, #[e], stepOf e⟩
    | none =>
      if e.op != 0 then return (ops, some s!"line {e.line}: the first operation is {e.op}, not 0")
      cur := some ⟨e.op, #[e], stepOf e⟩
  if let some o := cur then
    if o.op != 0 && o.step.isNone then return (ops, some s!"operation {o.op} has no step event")
    ops := ops.push o
  return (ops, none)

/-- Insert into a table; a different value for a known key is an error. -/
def insertFn {α β : Type} [BEq α] [Hashable α] [BEq β] (what : String) (m : HashMap α β)
    (k : α) (v : β) : Except String (HashMap α β) :=
  match m[k]? with
  | some v' =>
    if v' == v then .ok m else .error s!"{what} returned two different values for one argument"
  | none => .ok (m.insert k v)

/-- A table entry: the arguments and the value of one primitive. -/
inductive Entry where
  | hkdf (k : Bytes × Bytes × Bytes × Nat) (v : Bytes)
  | hmac (k : Bytes × Bytes) (v : Bytes)
  | keyGen (r : Bytes) (v : Bytes × Bytes × Bytes)
  | encaps1 (k : Bytes × Bytes) (v : Bytes × Bytes × Bytes)
  | encaps2 (k : Bytes × Bytes) (v : Bytes)
  | decaps (k : Bytes × Bytes × Bytes) (v : Bytes)
  | ekMatches (k : Bytes × Bytes) (v : Bool)
  | message (d : MDec) (v : Option Bytes)
  | parity (enc : MEnc) (c : MChunk)

/-- Add an entry to a table (`insertFn`). -/
def Tables.add (T : Tables) : Entry → Except String Tables
  | .hkdf k v => return { T with hkdf := ← insertFn "hkdf" T.hkdf k v }
  | .hmac k v => return { T with hmac := ← insertFn "hmac" T.hmac k v }
  | .keyGen r v => return { T with keyGen := ← insertFn "generate" T.keyGen r v }
  | .encaps1 k v => return { T with encaps1 := ← insertFn "encaps1" T.encaps1 k v }
  | .encaps2 k v => return { T with encaps2 := ← insertFn "encaps2" T.encaps2 k v }
  | .decaps k v => return { T with decaps := ← insertFn "decaps" T.decaps k v }
  | .ekMatches k v =>
    return { T with ekMatches := ← insertFn "ek_matches_header" T.ekMatches k v }
  | .message d v => return { T with message := ← insertFn "decoder" T.message d v }
  | .parity enc c => return { T with parity := ← insertFn "encoder" T.parity enc c }

/-- The entry of a primitive call event whose arguments give the primitive's input, or `none` for
any other event. A `decoder.message` event gives `none`; `decoded` handles it. -/
def parseCall (e : Event) : Except String (Option Entry) := do
  let a := e.args
  let triple (what : String) : Except String (Bytes × Bytes × Bytes) := do
    let r ← match e.ret with | .arr r => pure r | _ => throw s!"{what}: bad result"
    return (← argBytes r 0, ← argBytes r 1, ← argBytes r 2)
  match e.f with
  | "hkdf" =>
    let k := (← argBytes a 0, ← argBytes a 1, ← argBytes a 2, ← jNat (← arg a 3))
    return some (.hkdf k (← jBytes e.ret))
  | "hmac" =>
    let k := (← argBytes a 0, ← argBytes a 1)
    return some (.hmac k (← jBytes e.ret))
  | "mlkem.generate" =>
    let v ← triple "generate"
    return some (.keyGen (← argBytes a 0) v)
  | "mlkem.encaps1" =>
    let v ← triple "encaps1"
    return some (.encaps1 (← argBytes a 0, ← argBytes a 1) v)
  | "mlkem.encaps2" =>
    -- logged as `[ek, es]`, keyed as `(es, ek)` like the model's `Encaps2`
    let k := (← argBytes a 1, ← argBytes a 0)
    return some (.encaps2 k (← jBytes e.ret))
  | "mlkem.decaps" =>
    let k := (← argBytes a 0, ← argBytes a 1, ← argBytes a 2)
    return some (.decaps k (← jBytes e.ret))
  | "mlkem.ek_matches_header" =>
    -- logged as `[ek, hdr]`, keyed as `(hdr, ek)` like the model's `ekMatches`
    let k := (← argBytes a 1, ← argBytes a 0)
    return some (.ekMatches k (← e.ret.getBool?))
  | _ => return none

/-- Add an entry to the table `T` of one operation and to the table `all` of all operations. -/
def addEntry (T all : Tables) (x : Entry) : Except String (Tables × Tables) :=
  return (← T.add x, ← all.add x)

/-- Add the entry of an event, if it is a primitive call, to the tables `T` and `all`. -/
def addCall (T all : Tables) (e : Event) : Except String (Tables × Tables) := do
  match ← parseCall e with
  | some x => addEntry T all x
  | none => return (T, all)

/-- The decoder that `receive` adds the chunk of `m` to in state `σ`, with the chunk added, when
`receive` reaches `receiveEq` with an existing decoder. -/
def decoderAfter (σ : State MEnc MDec) (m : Msg MChunk) : Option MDec :=
  if m.epoch != σ.epoch then none else
  match σ, m.payload with
  | .headerSent _ _ _ d _, .ct1 c
  | .ekSentCt1Received _ _ _ _ d, .ct2 c
  | .noHeaderReceived _ _ d, .hdr c
  | .ct1Sampled _ _ _ _ _ _ d, .ek c
  | .ct1Sampled _ _ _ _ _ _ d, .ekCt1Ack c
  | .ct1Acknowledged _ _ _ _ _ d, .ek c
  | .ct1Acknowledged _ _ _ _ _ d, .ekCt1Ack c => some (d.addChunk c)
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

/-- Which primitive value of a step is missing, for the report. It follows `sendM` and
`receiveEqM` for the transitions that use primitives. -/
def explainMissing (Q : OPrims MEnc MDec MChunk) (σ : State MEnc MDec) : Obs MChunk → String
  | .send r _ _ _ _ =>
    match σ with
    | .keysUnsampled e a =>
      match Q.keyGen r with
      | none => "no generate call for the randomness"
      | some kg => match Auth.macHdrM Q a e kg.2.1 with
        | none => "no hmac call with the key and data of the header MAC"
        | some _ => "no chunk of the header encoder"
    | .headerReceived e a hdr _ =>
      match Q.encaps1 hdr r with
      | none => "no encaps1 call for the header and randomness"
      | some x => match Q.kdfOk x.2.2 e with
        | none => "no hkdf call for KDF_OK"
        | some ss => match Auth.updateM Q a e ss with
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
            | some ss => match Auth.updateM Q a e ss with
              | none => "no hkdf call for KDF_AUTH"
              | some a' => match Auth.macCtM Q a' e (ct1 ++ msg.take Q.ct2Size) with
                | none => "no hmac call with the key and data of the ciphertext MAC (verify_ct)"
                | some _ => "unknown"
        | .noHeaderReceived e a _ =>
          match Auth.macHdrM Q a e (msg.take Q.headerSize) with
          | none => "no hmac call with the key and data of the header MAC (verify_hdr)"
          | some _ => "unknown"
        | .ct1Sampled _ _ hdr .. | .ct1Acknowledged _ _ hdr .. =>
          match Q.ekMatches hdr msg with
          | none => "no ek_matches_header call"
          | some _ => "no encaps2 call, or no hmac call with the key and data of the ciphertext \
          MAC, for the ct2 encoder"
        | _ => "unknown"

/-- The differences between the model's key `k'` and state `σ'` and the observed key `k`, state
name `l` and epoch `e`, for the report. -/
def resultDiffs (k' k : Option Key) (σ' : State MEnc MDec) (l : Label) (e : Nat) :
    List (Option String) :=
  [if k'.map (·.1) != k.map (·.1) then some "key epoch" else none,
    if k' != k && k'.map (·.1) == k.map (·.1) then some "key bytes" else none,
    if σ'.label != l then some s!"state (model {repr σ'.label}, code {repr l})" else none,
    if σ'.epoch != e then some s!"epoch (model {σ'.epoch}, code {e})" else none]

/-- Why `checkStep Q σ o` fails, for the report. -/
def explainStep (Q : OPrims MEnc MDec MChunk) (σ : State MEnc MDec) (o : Obs MChunk) : String :=
  match o with
  | .send r m k l e =>
    match sendM Q σ r with
    | none => s!"missing primitive value: {explainMissing Q σ o}"
    | some (σ', m', k') =>
      let d := [if m'.epoch != m.epoch then some "message epoch" else none,
        if m'.payload.ctorIdx != m.payload.ctorIdx then some "payload kind" else none,
        if m' != m && m'.epoch == m.epoch && m'.payload.ctorIdx == m.payload.ctorIdx
          then some "chunk index or bytes" else none] ++ resultDiffs k' k σ' l e
      s!"send differs from the model in: {", ".intercalate d.reduceOption}"
  | .recvOk m k l e =>
    match receiveM Q σ m with
    | none => s!"missing primitive value: {explainMissing Q σ o}"
    | some none => "the model's Receive() fails, the code accepted"
    | some (some (σ', k')) =>
      s!"recv differs from the model in: {", ".intercalate (resultDiffs k' k σ' l e).reduceOption}"
  | .recvErr m =>
    match receiveM Q σ m with
    | none => s!"missing primitive value: {explainMissing Q σ o}"
    | some (some _) => "the model's Receive() succeeds, the code returned an error"
    | some none => "unknown"

/-- The randomness of an operation: the seed of its `generate` call or the randomness of its
`encaps1` call, if any. -/
def randomness (o : Operation) : Except String Bytes := do
  let rs ← o.events.filterMapM fun e =>
    match e.f with
    | "mlkem.generate" => some <$> argBytes e.args 0
    | "mlkem.encaps1" => some <$> argBytes e.args 1
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
  -- a malformed operation is reported only if the replay reaches it
  let (ops, malformed) := operations evs
  -- `operations` makes `ops[0]` operation 0
  let some init := ops[0]? | return fail (malformed.getD "no initialization") 0
  if let some e := init.step then
    return fail s!"line {e.line}: step event in the initialization (operation 0)" 0
  let inits := init.events.filter (·.f == "init")
  let some ie := inits[0]? | return fail "no init event" 0
  if inits.size != 1 then return fail "two init events in the initialization" 0
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
  if let some e := init.events.find? (·.f == "decoder.message") then
    return fail s!"line {e.line}: decoder result in the initialization (operation 0)" 0
  for e in init.events do
    match addCall T0 all e with
    | .ok (t, a) => T0 := t; all := a
    | .error err => return fail err 0
  let Q0 := T0.prims
  let σ0? := if party == "A" then initAliceM Q0 ss else initBobM Q0 ss
  let some σ0 := σ0? | return fail "initialization: no hkdf call for the authenticator" 0
  -- learning pass: one table per operation, replayed with the checker's own step function, up to
  -- and including the first step that fails
  let mut steps : Array (OPrims MEnc MDec MChunk × Obs MChunk) := #[]
  let mut σ : State MEnc MDec := σ0
  let mut firstFail : Option String := none
  for o in ops[1:] do
    let some se := o.step | return fail s!"operation {o.op} has no step event" steps.size
    if let some e := o.events.find? (·.f == "init") then
      return fail s!"line {e.line}: init event in operation {o.op}" steps.size
    let r ← match randomness o with
      | .ok r => pure r
      | .error err => return fail err steps.size
    let obs ← match parseObs se r with
      | .ok obs => pure obs
      | .error err => return fail s!"line {se.line}: {err}" steps.size
    let mut T : Tables := {}
    for e in o.events do
      match addCall T all e with
      | .ok (t, a) => T := t; all := a
      | .error err => return fail s!"line {e.line}: {err}" steps.size
    -- the state before the call, as the code logged it, is the model's state
    let pre : Except String (Label × Nat) := do
      return (← jLabel (← arg se.args 0), ← jNat (← arg se.args 1))
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
        if d.size != 2 * pts then
          return fail s!"operation {o.op}: decoder of {d.size} bytes, code needs {pts} points"
            steps.size
        match addEntry T all (.message d res) with
        | .ok (t, a) => T := t; all := a
        | .error err => return fail s!"operation {o.op}: {err}" steps.size
      else
        return fail s!"operation {o.op}: a decoder result, but the model's step adds the chunk to \
          no decoder" steps.size
    | _, .ok (some _) =>
      return fail s!"operation {o.op}: a decoder result in an operation that is not a receive"
        steps.size
    | _, .error err => return fail err steps.size
    | _, .ok none => pure ()
    -- the parity chunk of a send
    match obs, encoderOf σ with
    | .send _ m .., some enc =>
      if enc.2 ≥ 65536 then
        return fail s!"operation {o.op}: chunk number {enc.2} of an encoder; the monitor supports \
          chunk numbers below 65536" steps.size
      if enc.2 ≥ enc.1.length / 32 then
        if let some c := chunkOf m.payload then
          if c.index != enc.2 || c.data.length != 32 then
            return fail s!"operation {o.op}: parity chunk #{c.index} of {c.data.length} bytes, \
              expected index {enc.2} and 32 bytes" steps.size
          match addEntry T all (.parity enc c) with
          | .ok (t, a) => T := t; all := a
          | .error err => return fail s!"operation {o.op}: {err}" steps.size
    | _, _ => pure ()
    let Q := T.prims
    match checkStep Q σ obs with
    | some σ' =>
      σ := σ'
      steps := steps.push (Q, obs)
    | none =>
      let why := explainStep Q σ obs
      -- only when the model's step needs one specific HMAC that the operation did not log
      let calls := (o.events.filter (·.f == "hmac")).size
      let other := if why.startsWith "missing primitive value: no hmac call" && calls > 0 then
          s!" (this operation logged {calls} hmac call(s), on other keys or data)"
        else ""
      firstFail := some s!"operation {o.op} (line {se.line}), {se.f} in {State.describe σ}, \
        message {describeMsg (obsMsg obs)}: {why}{other}"
      steps := steps.push (Q, obs)
      break
  if firstFail.isNone then
    if let some err := malformed then return fail err steps.size
  -- the verdict of the verified checker
  match checkRun σ0 steps.toList with
  | some _ =>
    if let some f := firstFail then
      return fail s!"internal: the learning pass failed but checkRun accepts: {f}" steps.size
    ⟨party, steps.size, .ok (), obsKeys (steps.toList.map (·.2))⟩
  | none =>
    fail (firstFail.getD "rejected (no diagnosis)") steps.size

/-- The keys logged in the step events of `evs`, in order, whether or not the checker accepted
the party. A step event without a key that parses is skipped. -/
def loggedKeys (evs : Array Event) : List Key :=
  evs.toList.filterMap fun e =>
    if e.isStep then
      match e.ret.getObjVal? "key" >>= parseKey with
      | .ok (some key) => some key
      | _ => none
    else none

/-- The results of the session-level checks (`sessionChecks`). -/
structure SessionChecks where
  delivery : Except String Unit
  keys : Except String Unit
  incompleteEpochs : List Nat
  randomness : Except String Unit

/-- Whether `t` is a tampered copy of `m`: a chunk message with the same epoch, payload kind,
chunk index and chunk length, and other chunk bytes. -/
def tamperedCopy (m t : Msg MChunk) : Bool :=
  match chunkOf m.payload, chunkOf t.payload with
  | some c, some d =>
    m.epoch == t.epoch && m.payload.ctorIdx == t.payload.ctorIdx && c.index == d.index &&
      c.data.length == d.data.length && c.data != d.data
  | _, _ => false

/-- `sent` with one fewer send of `k`; a key with no sends left is erased. -/
def consume (sent : HashMap (String × String) Nat) (k : String × String) :
    HashMap (String × String) Nat :=
  match sent[k]? with
  | some (n + 2) => sent.insert k (n + 1)
  | _ => sent.erase k

/-- The session-level checks of the events `evs` of one session, with the keys `ka` and `kb` of
parties A and B.

* `delivery`: each receive consumes an earlier equal send of the other party, or receives the
  logged tampered copy of an unconsumed send (`tamperedCopy`); a receive of the copy that
  succeeds consumes that send.
* `keys`: each party has at most one key per epoch, and the two parties' keys of an epoch are
  equal; `incompleteEpochs` lists the epochs with a key from one party only.
* `randomness`: no two `generate` or `encaps1` calls get the same randomness. -/
def sessionChecks (evs : Array Event) (ka kb : List Key) : SessionChecks := Id.run do
  let mut sent : HashMap (String × String) Nat := {}
  -- the tamper event waiting for its receive: line, party, operation, copy, and the send key of
  -- the original
  let mut pending : Option (Nat × String × Nat × String × (String × String)) := none
  let mut delivery : Except String Unit := .ok ()
  let mut seen : HashSet String := {}
  let mut randomness : Except String Unit := .ok ()
  for e in evs do
    let peer := if e.party == "A" then "B" else "A"
    if let some (l, p, op, _, _) := pending then
      if delivery.isOk && (e.party != p || e.op != op) then
        delivery := .error s!"line {l}: the operation of the tamper event does not receive the \
          tampered copy"
        pending := none
    if e.f == "States::send" then
      if let .ok m := e.ret.getObjVal? "msg" then
        let k := (e.party, m.compress)
        sent := sent.insert k (sent.getD k 0 + 1)
    else if e.f == "States::recv" && delivery.isOk then
      if let some m := e.args[2]? then
        match pending with
        | some (l, _, _, c, k) =>
          if m.compress != c then
            delivery := .error s!"line {e.line}: party {e.party} received another message than \
              the tampered copy of the tamper event on line {l}"
          -- an accepted copy replaces the original, which then cannot be received
          else if !(e.ret.getObjVal? "err").isOk then
            sent := consume sent k
          pending := none
        | none =>
          let k := (peer, m.compress)
          match sent[k]? with
          | some _ => sent := consume sent k
          | _ => delivery := .error s!"line {e.line}: party {e.party} received a message that \
              party {peer} did not send"
    else if e.f == "tamper" && delivery.isOk then
      match e.args[0]?, e.args[1]? with
      | some o, some t =>
        match parseMsg o, parseMsg t with
        | .ok mo, .ok mt =>
          if pending.isSome then
            delivery := .error s!"line {e.line}: two tamper events in one operation"
          else if sent.getD (peer, o.compress) 0 == 0 then
            delivery := .error s!"line {e.line}: party {e.party} received a tampered copy of a \
              message that party {peer} did not send"
          else if !tamperedCopy mo mt then
            delivery := .error s!"line {e.line}: the tampered message differs from the original \
              in more than the chunk bytes"
          else
            pending := some (e.line, e.party, e.op, t.compress, (peer, o.compress))
        | _, _ => delivery := .error s!"line {e.line}: bad message in a tamper event"
      | _, _ => delivery := .error s!"line {e.line}: a tamper event needs two messages"
    else if (e.f == "mlkem.generate" || e.f == "mlkem.encaps1") && randomness.isOk then
      let i := if e.f == "mlkem.generate" then 0 else 1
      if let some r := e.args[i]? then
        let s := r.compress
        if seen.contains s then
          randomness := .error s!"line {e.line}: {e.f} reuses randomness of an earlier call"
        seen := seen.insert s
  if let some (l, _, _, _, _) := pending then
    if delivery.isOk then
      delivery := .error s!"line {l}: the operation of the tamper event does not receive the \
        tampered copy"
  let toMap (ks : List Key) : Except String (HashMap Nat Bytes) :=
    ks.foldlM (init := {}) fun m (ep, s) =>
      if m.contains ep then .error s!"two keys for epoch {ep}" else .ok (m.insert ep s)
  let keys : Except String Unit × List Nat := match toMap ka, toMap kb with
    | .error err, _ => (.error s!"party A: {err}", [])
    | _, .error err => (.error s!"party B: {err}", [])
    | .ok ma, .ok mb =>
      let eps := (ma.keys ++ mb.keys.filter (!ma.contains ·)).mergeSort
      let differs (ep : Nat) : Bool := match ma[ep]?, mb[ep]? with
        | some a, some b => a != b
        | _, _ => false
      let r := match eps.find? differs with
        | some ep => .error s!"epoch {ep}: the parties' secrets differ"
        | none => .ok ()
      (r, eps.filter fun ep => !(ma.contains ep && mb.contains ep))
  ⟨delivery, keys.1, keys.2, randomness⟩

end Monitor
