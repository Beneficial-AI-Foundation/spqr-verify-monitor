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
check of every file passes, 3 when every check passes on a prefix (`--max-ops`), 1 when a check
fails, and 2 on a usage error. -/

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
  -- the events of each session, sessions in order of their first event
  let mut index : HashMap Nat Nat := {}
  let mut sessions : Array (Nat × Array Event) := #[]
  for e in evs do
    match index[e.session]? with
    | some i => sessions := sessions.modify i fun (s, a) => (s, a.push e)
    | none =>
      index := index.insert e.session sessions.size
      sessions := sessions.push (e.session, #[e])
  let mut ok := true
  IO.println s!"{path}: {evs.size} events, {sessions.size} session(s)"
  if sessions.isEmpty then
    IO.println "  REJECTED: no events"
    return false
  for (s, sevs₀) in sessions do
    let mut sevs := sevs₀
    if let some n := maxOps then
      let cut := sevs.filter (·.op ≤ n)
      if cut.size < sevs.size then
        IO.println s!"  session {s}: PARTIAL, only operations 0..{n} of this session are checked"
        -- keep whole operations only
        sevs := cut
    -- only parties A and B; operations numbered 0, 1, 2, ... in file order
    let mut last := 0
    for e in sevs do
      if e.party != "A" && e.party != "B" then
        ok := false
        IO.println s!"  session {s}: REJECTED: line {e.line}: unknown party {e.party}"
        break
      if e.op != last && e.op != last + 1 then
        ok := false
        IO.println s!"  session {s}: REJECTED: line {e.line}: operation {e.op} after \
          operation {last}"
        break
      last := e.op
    -- every operation other than the initializations (operation 0) belongs to one party
    let mut owner : HashMap Nat String := {}
    for e in sevs do
      if e.op == 0 then continue
      match owner[e.op]? with
      | some p =>
        if p != e.party then
          ok := false
          IO.println s!"  session {s}: REJECTED: line {e.line}: operation {e.op} has events of \
            parties {p} and {e.party}"
          break
      | none => owner := owner.insert e.op e.party
    let evA := sevs.filter (·.party == "A")
    let evB := sevs.filter (·.party == "B")
    for (p, pevs) in [("A", evA), ("B", evB)] do
      if pevs.isEmpty then
        ok := false
        IO.println s!"  session {s} party {p}: REJECTED: no events for this party"
        continue
      let r := checkParty p pevs
      match r.verdict with
      | .ok () =>
        IO.println s!"  session {s} party {p}: ACCEPTED ({r.operations} operations, \
          {r.keys.length} keys)"
      | .error err =>
        ok := false
        IO.println s!"  session {s} party {p}: REJECTED: {err}"
    -- key agreement uses the keys the code logged, so it also holds for a rejected party
    let c := sessionChecks sevs (loggedKeys evA) (loggedKeys evB)
    ok := (← report s "delivery" c.delivery) && ok
    ok := (← report s "key agreement" c.keys) && ok
    if !c.incompleteEpochs.isEmpty then
      IO.println s!"  session {s} key agreement: incomplete epochs (one party only) \
        {c.incompleteEpochs}"
    ok := (← report s "randomness reuse (outside BraidModel)" c.randomness) && ok
  return ok

/-- Check the files given on the command line; see the module docstring for the exit code. -/
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
    if !ok then
      IO.println "SOME CHECKS FAILED"; return 1
    if maxOps.isSome then
      IO.println "ALL CHECKS PASSED ON THE CHECKED PREFIX (partial coverage, exit code 3)"
      return 3
    IO.println "ALL CHECKS PASSED"
    return 0
