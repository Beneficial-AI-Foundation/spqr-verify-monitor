/-
Copyright (c) 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Lacramioara Astefanoaei
-/
import Monitor.Check

/-! # `spqr-monitor`: check event logs against `BraidModel`

Usage: `spqr-monitor [--max-ops N] <trace.jsonl>...`

For each file and each session in it, the program checks both parties (`Monitor.checkParty`)
and the session-level properties (`Monitor.sessionChecks`), and prints one line per party and
per check. With `--max-ops N` it checks only the events up to the `N`-th operation of each
session, and says so: that is partial coverage of the file. The exit code is 0 when every
check of every file passes. -/

open Lean Std Monitor

/-- Read a file into events. -/
def readEvents (path : String) : IO (Array Event) := do
  let text ← IO.FS.readFile path
  let mut evs : Array Event := #[]
  let mut n := 0
  for line in text.splitOn "\n" do
    n := n + 1
    if line.isEmpty then continue
    match parseEvent n line with
    | .ok e => evs := evs.push e
    | .error err => throw (IO.userError s!"{path}:{n}: {err}")
  return evs

/-- Print the result of a session check; return whether it passed. -/
def report (s : Nat) (what : String) (r : Except String Unit) : IO Bool := do
  match r with
  | .ok () => IO.println s!"  session {s} {what}: ok"; return true
  | .error err => IO.println s!"  session {s} {what}: FAILED: {err}"; return false

/-- Check one file; return whether every check passed. -/
def checkFile (path : String) (maxOps : Option Nat) : IO Bool := do
  let evs ← readEvents path
  let sessions := (evs.map (·.session)).toList.eraseDups
  let mut ok := true
  IO.println s!"{path}: {evs.size} events, {sessions.length} session(s)"
  for s in sessions do
    let mut sevs := evs.filter (·.session == s)
    if let some n := maxOps then
      let cut := sevs.filter (·.op ≤ n)
      if cut.size < sevs.size then
        IO.println s!"  session {s}: PARTIAL, only operations 0..{n} of this session are checked"
        -- keep whole operations only
        sevs := cut
    let mut keys : HashMap String (List BraidModel.Key) := {}
    for p in ["A", "B"] do
      let pevs := sevs.filter (·.party == p)
      if pevs.isEmpty then continue
      let r := checkParty p pevs
      keys := keys.insert p r.keys
      match r.verdict with
      | .ok () =>
        IO.println s!"  session {s} party {p}: ACCEPTED ({r.operations} operations, \
          {r.keys.length} keys)"
      | .error err =>
        ok := false
        IO.println s!"  session {s} party {p}: REJECTED: {err}"
    let c := sessionChecks sevs (keys.getD "A" []) (keys.getD "B" [])
    ok := (← report s "delivery" c.delivery) && ok
    ok := (← report s "key agreement" c.keys) && ok
    if !c.incompleteEpochs.isEmpty then
      IO.println s!"  session {s} key agreement: incomplete epochs (one party only) \
        {c.incompleteEpochs}"
    ok := (← report s "randomness reuse (outside BraidModel)" c.randomness) && ok
  return ok

def main (args : List String) : IO UInt32 := do
  let rec parse : List String → Option Nat → List String → Except String (Option Nat × List String)
    | [], m, fs => .ok (m, fs.reverse)
    | "--max-ops" :: n :: rest, _, fs => match n.toNat? with
      | some k => parse rest (some k) fs
      | none => .error s!"bad --max-ops {n}"
    | f :: rest, m, fs => parse rest m (f :: fs)
  match parse args none [] with
  | .error err => IO.eprintln err; return 2
  | .ok (_, []) => IO.eprintln "usage: spqr-monitor [--max-ops N] <trace.jsonl>..."; return 2
  | .ok (maxOps, files) =>
    let mut ok := true
    for f in files do
      ok := (← checkFile f maxOps) && ok
    IO.println (if ok then "ALL CHECKS PASSED" else "SOME CHECKS FAILED")
    return if ok then 0 else 1
