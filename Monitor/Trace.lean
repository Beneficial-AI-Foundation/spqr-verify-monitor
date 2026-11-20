/-
Copyright (c) 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Lacramioara Astefanoaei
-/
import Lean.Data.Json
import Monitor.Tables

/-! # Reading the event log

The Rust feature `monitor` (`src/monitor.rs`) writes one JSON object per line:
`{"s":session,"p":party,"op":operation,"f":function,"args":[..],"ret":..}`, with bytes as
lowercase hex. This module parses the lines into `Event`s, and the step events (`States::send`,
`States::recv`) into observations (`BraidModel.Obs`). -/

open Lean Aeneas Aeneas.Std BraidModel

namespace Monitor

/-- One logged call. `line` is its line number in the file, from 1. -/
structure Event where
  line : Nat
  session : Nat
  party : String
  op : Nat
  f : String
  args : Array Json
  ret : Json
  deriving Inhabited

/-- The value of a hex digit. -/
def hexDigit (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else none

/-- The bytes of a lowercase hex string. -/
def decodeHex (s : String) : Except String Bytes := do
  let rec go : List Char → Array Std.U8 → Except String (Array Std.U8)
    | [], acc => .ok acc
    | a :: b :: rest, acc =>
      match hexDigit a, hexDigit b with
      | some x, some y => go rest (acc.push (byte (16 * x + y)))
      | _, _ => .error s!"bad hex digit in {s.take 16}"
    | [_], _ => .error "odd number of hex digits"
  return (← go s.toList #[]).toList

/-- The bytes of a JSON hex string. -/
def jBytes (j : Json) : Except String Bytes := do decodeHex (← j.getStr?)

/-- A natural number in JSON. -/
def jNat (j : Json) : Except String Nat := j.getNat?

/-- The `i`-th byte string of a JSON argument array. -/
def argBytes (a : Array Json) (i : Nat) : Except String Bytes := do
  match a[i]? with
  | some j => jBytes j
  | none => throw s!"missing argument {i}"

/-- The `i`-th element of an argument array. -/
def arg (a : Array Json) (i : Nat) : Except String Json :=
  match a[i]? with
  | some j => .ok j
  | none => .error s!"missing argument {i}"

/-- Parse one line. -/
def parseEvent (line : Nat) (s : String) : Except String Event := do
  let j ← Json.parse s
  let args ← match ← j.getObjVal? "args" with
    | .arr a => pure a
    | _ => throw "args is not an array"
  return {
    line
    session := ← jNat (← j.getObjVal? "s")
    party := ← (← j.getObjVal? "p").getStr?
    op := ← jNat (← j.getObjVal? "op")
    f := ← (← j.getObjVal? "f").getStr?
    args
    ret := ← j.getObjVal? "ret" }

/-- The name of a state, from the `States` variant name. -/
def parseLabel (s : String) : Except String Label :=
  match s with
  | "KeysUnsampled" => .ok .keysUnsampled
  | "KeysSampled" => .ok .keysSampled
  | "HeaderSent" => .ok .headerSent
  | "Ct1Received" => .ok .ct1Received
  | "EkSentCt1Received" => .ok .ekSentCt1Received
  | "NoHeaderReceived" => .ok .noHeaderReceived
  | "HeaderReceived" => .ok .headerReceived
  | "Ct1Sampled" => .ok .ct1Sampled
  | "EkReceivedCt1Sampled" => .ok .ekReceivedCt1Sampled
  | "Ct1Acknowledged" => .ok .ct1Acknowledged
  | "Ct2Sampled" => .ok .ct2Sampled
  | _ => .error s!"unknown state {s}"

/-- The name of a state, from a JSON string. -/
def jLabel (j : Json) : Except String Label := do parseLabel (← j.getStr?)

/-- A chunk `{index, data}`. -/
def parseChunk (j : Json) : Except String MChunk := do
  return ⟨← jNat (← j.getObjVal? "index"), ← jBytes (← j.getObjVal? "data")⟩

/-- A message `{epoch, kind, ...}`. As in `absMsg` (`Relation.lean`), `Ct1Ack(false)` is the
`None` payload. -/
def parseMsg (j : Json) : Except String (Msg MChunk) := do
  let epoch ← jNat (← j.getObjVal? "epoch")
  let payload ← match ← (← j.getObjVal? "kind").getStr? with
    | "none" => pure Payload.none
    | "ct1ackfalse" => pure Payload.none
    | "ct1ack" => pure Payload.ct1Ack
    | "hdr" => pure (Payload.hdr (← parseChunk j))
    | "ek" => pure (Payload.ek (← parseChunk j))
    | "ekct1ack" => pure (Payload.ekCt1Ack (← parseChunk j))
    | "ct1" => pure (Payload.ct1 (← parseChunk j))
    | "ct2" => pure (Payload.ct2 (← parseChunk j))
    | k => throw s!"unknown message kind {k}"
  return ⟨epoch, payload⟩

/-- A key: `null` or `{epoch, secret}`. -/
def parseKey (j : Json) : Except String (Option Key) := do
  if j.isNull then return none
  return some (← jNat (← j.getObjVal? "epoch"), ← jBytes (← j.getObjVal? "secret"))

/-- The key, state name and epoch of a successful step result `{key, state, epoch, ...}`. -/
def parseResult (ret : Json) : Except String (Option Key × Label × Nat) := do
  return (← parseKey (← ret.getObjVal? "key"), ← jLabel (← ret.getObjVal? "state"),
    ← jNat (← ret.getObjVal? "epoch"))

/-- The observation of a step event, with the randomness `r` of its operation. -/
def parseObs (e : Event) (r : Bytes) : Except String (Obs MChunk) := do
  match e.f with
  | "States::send" =>
    if (e.ret.getObjVal? "err").isOk then throw "States::send returned an error"
    let m ← parseMsg (← e.ret.getObjVal? "msg")
    let (k, l, ep) ← parseResult e.ret
    return .send r m k l ep
  | "States::recv" =>
    let m ← parseMsg (← arg e.args 2)
    if (e.ret.getObjVal? "err").isOk then return .recvErr m
    let (k, l, ep) ← parseResult e.ret
    return .recvOk m k l ep
  | f => throw s!"{f} is not a step event"

/-- Whether an event is a step event (`States::send` or `States::recv`). -/
def Event.isStep (e : Event) : Bool := e.f == "States::send" || e.f == "States::recv"

end Monitor
