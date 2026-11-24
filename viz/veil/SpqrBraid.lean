module

public import Veil

/-! # The ML-KEM Braid of SPQR, abstracted for Veil

A hand-written abstraction of `BraidModel` (`Spqr/Specs/Braid/StateMachine/Model.lean`) for
Veil. It is a second model, not derived from `BraidModel`: nothing links the two except that
the actions below follow the arms of `send`, `receiveEq` and `receive` of `BraidModel`. Most
actions are one arm; `recv_chunk`, `recv_noop`, `recv_older` and the failure actions each
cover a case that several arms share, and transitions (11) and (12) are split by message type.
A trace query names the action of each step: Veil's trace queries take action names only.

What the abstraction keeps: the eleven labels of §2.5, the epoch of each party as a `Nat`,
the message type, the epoch of a message relative to the receiver's epoch, whether an output
key is emitted, and the messages each party sent (type and epoch).

What it drops:
- Bytes. Chunks, chunk indexes, keys, ciphertexts and MAC values are gone.
- Decoders. Whether a chunk completes a decoder is not modeled: the arm a step takes
  (complete or not) is read from the logged state after the step.
- The MAC equality. A MAC check is an observation `mac` of the operation: `absent` (no MAC
  call), `good` (every MAC call has input of the §2.4 form that the step computes, `MacHdr`
  at (1) and (6) and `MacCt` otherwise, and a `MacCt` input matches the
  ciphertexts of one logged `decaps`, and its `ct2` part the result of one logged `encaps2`) or
  `bad`. `trace2veil.py` decides this outside Veil. Whether the MAC value matches is not
  modeled: a failed check (`err_mac`) needs only a `good` call.
- The `ek` integrity check. Its result is not modeled: `err_ek` needs only a state that checks
  `ek` and an `ek` message that the peer sent.
- KEM correctness and key agreement. Two parties can emit keys for one epoch with no relation
  between them.
- Delivery of older and later messages. A successful receive of the receiver's epoch, and the
  receive of the next epoch at (13), need a message that the peer sent; a receive of an older
  epoch and a failed receive of a later epoch (`err_future`) do not.
-/

veil module SpqrBraid

enum party = { pA, pB }

/- The eleven states of §2.5. -/
enum blabel = { keysUnsampled, keysSampled, headerSent, ct1Received, ekSentCt1Received,
  noHeaderReceived, headerReceived, ct1Sampled, ekReceivedCt1Sampled, ct1Acknowledged,
  ct2Sampled }

/- The message types of §2.3 (`Payload`). -/
enum kind = { kNone, kHdr, kEk, kEkCt1Ack, kCt1Ack, kCt1, kCt2 }

/- The epoch of a received message relative to the receiver's epoch `e`: below `e`, `e`,
`e + 1`, or above `e + 1`. -/
enum erel = { older, same, next, later }

/- The MAC calls of one operation, as classified by `trace2veil.py`. -/
enum macObs = { absent, good, bad }


function lab : party → blabel
function ep : party → Nat
/- `sent p k e`: party `p` sent a message of type `k` in epoch `e`. -/
relation sent : party → kind → Nat → Bool

-- The observation of the last step, so that a trace query can pin it with `assert`.
individual lastParty : party
individual lastKind : kind
individual lastRel : erel
individual lastMac : macObs
individual lastKey : Bool

#gen_state

/- `InitAlice` and `InitBob` (§2.6). -/
after_init {
  lab P := if P = pA then keysUnsampled else noHeaderReceived
  ep P := 1
  sent P K E := false
  lastParty := pA
  lastKind := kNone
  lastRel := same
  lastMac := absent
  lastKey := false
}

/-! ## Send: the arms of `send` -/

/- Transition (1): `KeyGen`, `MacHdr`, first `Hdr` chunk. -/
action send_t1 (p : party) {
  require lab p = keysUnsampled
  lab p := keysSampled
  sent p kHdr (ep p) := true
  lastParty := p
  lastKind := kHdr
  lastRel := same
  lastMac := good
  lastKey := false
}

/- Transition (7): `Encaps1`, `KDF_OK`, `Update`, first `Ct1` chunk, and an output key. -/
action send_t7 (p : party) {
  require lab p = headerReceived
  lab p := ct1Sampled
  sent p kCt1 (ep p) := true
  lastParty := p
  lastKind := kCt1
  lastRel := same
  lastMac := absent
  lastKey := true
}

/- `send` in `keysSampled`: the next `Hdr` chunk, no state change. -/
action send_keysSampled (p : party) {
  require lab p = keysSampled
  sent p kHdr (ep p) := true
  lastParty := p
  lastKind := kHdr
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- `send` in `headerSent`: the next `Ek` chunk, no state change. -/
action send_headerSent (p : party) {
  require lab p = headerSent
  sent p kEk (ep p) := true
  lastParty := p
  lastKind := kEk
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- `send` in `ct1Received`: the next `EkCt1Ack` chunk, no state change. -/
action send_ct1Received (p : party) {
  require lab p = ct1Received
  sent p kEkCt1Ack (ep p) := true
  lastParty := p
  lastKind := kEkCt1Ack
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- `send` in `ekSentCt1Received`: a `Ct1Ack` message, with no chunk data; no state change. -/
action send_ekSentCt1Received (p : party) {
  require lab p = ekSentCt1Received
  sent p kCt1Ack (ep p) := true
  lastParty := p
  lastKind := kCt1Ack
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- `send` in `noHeaderReceived`: a `None` message, with no chunk data; no state change. -/
action send_noHeaderReceived (p : party) {
  require lab p = noHeaderReceived
  sent p kNone (ep p) := true
  lastParty := p
  lastKind := kNone
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- `send` in `ct1Sampled`: the next `Ct1` chunk, no state change. -/
action send_ct1Sampled (p : party) {
  require lab p = ct1Sampled
  sent p kCt1 (ep p) := true
  lastParty := p
  lastKind := kCt1
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- `send` in `ekReceivedCt1Sampled`: the next `Ct1` chunk, no state change. -/
action send_ekReceivedCt1Sampled (p : party) {
  require lab p = ekReceivedCt1Sampled
  sent p kCt1 (ep p) := true
  lastParty := p
  lastKind := kCt1
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- `send` in `ct1Acknowledged`: a `None` message, with no chunk data; no state change. -/
action send_ct1Acknowledged (p : party) {
  require lab p = ct1Acknowledged
  sent p kNone (ep p) := true
  lastParty := p
  lastKind := kNone
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- `send` in `ct2Sampled`: the next `Ct2` chunk, no state change. -/
action send_ct2Sampled (p : party) {
  require lab p = ct2Sampled
  sent p kCt2 (ep p) := true
  lastParty := p
  lastKind := kCt2
  lastRel := same
  lastMac := absent
  lastKey := false
}

/-! ## Receive: the arms of `receiveEq` and `receive` that do not fail

Each arm for a message of the receiver's epoch requires that the peer sent a message of that
type in that epoch. -/

/- Transition (2): the first `Ct1` chunk starts the `Ct1` decoder. -/
action recv_t2 (p : party) {
  let q := if p = pA then pB else pA
  require lab p = keysSampled
  require sent q kCt1 (ep p)
  lab p := headerSent
  lastParty := p
  lastKind := kCt1
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- Transition (3): a `Ct1` chunk completes `ct1`. -/
action recv_t3 (p : party) {
  let q := if p = pA then pB else pA
  require lab p = headerSent
  require sent q kCt1 (ep p)
  lab p := ct1Received
  lastParty := p
  lastKind := kCt1
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- Transition (4): the first `Ct2` chunk starts the `Ct2` decoder. -/
action recv_t4 (p : party) {
  let q := if p = pA then pB else pA
  require lab p = ct1Received
  require sent q kCt2 (ep p)
  lab p := ekSentCt1Received
  lastParty := p
  lastKind := kCt2
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- Transition (5): a `Ct2` chunk completes `ct2 || mac`; `Decaps`, `KDF_OK`, `Update`, `MacCt` (verify), an output key, and the next epoch. -/
action recv_t5 (p : party) {
  let q := if p = pA then pB else pA
  require lab p = ekSentCt1Received
  require sent q kCt2 (ep p)
  lab p := noHeaderReceived
  ep p := ep p + 1
  lastParty := p
  lastKind := kCt2
  lastRel := same
  lastMac := good
  lastKey := true
}

/- Transition (6): a `Hdr` chunk completes `hdr || mac`; `MacHdr` (verify). -/
action recv_t6 (p : party) {
  let q := if p = pA then pB else pA
  require lab p = noHeaderReceived
  require sent q kHdr (ep p)
  lab p := headerReceived
  lastParty := p
  lastKind := kHdr
  lastRel := same
  lastMac := good
  lastKey := false
}

/- Transition (8): an `EkCt1Ack` chunk that does not complete `ek`. -/
action recv_t8 (p : party) {
  let q := if p = pA then pB else pA
  require lab p = ct1Sampled
  require sent q kEkCt1Ack (ep p)
  lab p := ct1Acknowledged
  lastParty := p
  lastKind := kEkCt1Ack
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- Transition (9): an `EkCt1Ack` chunk completes `ek`; `Encaps2` and `MacCt` for the `Ct2` encoder. -/
action recv_t9 (p : party) {
  let q := if p = pA then pB else pA
  require lab p = ct1Sampled
  require sent q kEkCt1Ack (ep p)
  lab p := ct2Sampled
  lastParty := p
  lastKind := kEkCt1Ack
  lastRel := same
  lastMac := good
  lastKey := false
}

/- Transition (10): an `Ek` chunk completes `ek`. -/
action recv_t10 (p : party) {
  let q := if p = pA then pB else pA
  require lab p = ct1Sampled
  require sent q kEk (ep p)
  lab p := ekReceivedCt1Sampled
  lastParty := p
  lastKind := kEk
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- Transition (11) on an `EkCt1Ack` chunk that completes `ek`; `Encaps2` and `MacCt`. -/
action recv_t11_ekct1ack (p : party) {
  let q := if p = pA then pB else pA
  require lab p = ct1Acknowledged
  require sent q kEkCt1Ack (ep p)
  lab p := ct2Sampled
  lastParty := p
  lastKind := kEkCt1Ack
  lastRel := same
  lastMac := good
  lastKey := false
}

/- Transition (11) on an `Ek` chunk that completes `ek` (`Deviation.lateEkChunk`); `Encaps2` and `MacCt`. -/
action recv_t11_ek (p : party) {
  let q := if p = pA then pB else pA
  require lab p = ct1Acknowledged
  require sent q kEk (ep p)
  lab p := ct2Sampled
  lastParty := p
  lastKind := kEk
  lastRel := same
  lastMac := good
  lastKey := false
}

/- Transition (12) on `EkCt1Ack`; `Encaps2` and `MacCt`. -/
action recv_t12_ekct1ack (p : party) {
  let q := if p = pA then pB else pA
  require lab p = ekReceivedCt1Sampled
  require sent q kEkCt1Ack (ep p)
  lab p := ct2Sampled
  lastParty := p
  lastKind := kEkCt1Ack
  lastRel := same
  lastMac := good
  lastKey := false
}

/- Transition (12) on `Ct1Ack` (`Deviation.ct1AckAccepted`); `Encaps2` and `MacCt`. -/
action recv_t12_ct1ack (p : party) {
  let q := if p = pA then pB else pA
  require lab p = ekReceivedCt1Sampled
  require sent q kCt1Ack (ep p)
  lab p := ct2Sampled
  lastParty := p
  lastKind := kCt1Ack
  lastRel := same
  lastMac := good
  lastKey := false
}

/- Transition (13): in `Ct2Sampled`, a message of the next epoch starts that epoch. -/
action recv_t13 (p : party) (k : kind) {
  let q := if p = pA then pB else pA
  require lab p = ct2Sampled
  require sent q k (ep p + 1)
  lab p := keysUnsampled
  ep p := ep p + 1
  lastParty := p
  lastKind := k
  lastRel := next
  lastMac := absent
  lastKey := false
}

/- A chunk that a decoder of the state takes but that does not complete it. -/
action recv_chunk (p : party) (k : kind) {
  let q := if p = pA then pB else pA
  require sent q k (ep p)
  require ((lab p = headerSent ∧ k = kCt1) ∨ (lab p = ekSentCt1Received ∧ k = kCt2) ∨
    (lab p = noHeaderReceived ∧ k = kHdr) ∨ (lab p = ct1Sampled ∧ k = kEk) ∨
    (lab p = ct1Acknowledged ∧ (k = kEkCt1Ack ∨ k = kEk)))
  lastParty := p
  lastKind := k
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- A message of the receiver's epoch that the state does not act on (the last arm of `receiveEq`). -/
action recv_noop (p : party) (k : kind) {
  let q := if p = pA then pB else pA
  require sent q k (ep p)
  require ¬ ((lab p = headerSent ∧ k = kCt1) ∨ (lab p = ekSentCt1Received ∧ k = kCt2) ∨
    (lab p = noHeaderReceived ∧ k = kHdr) ∨ (lab p = ct1Sampled ∧ (k = kEk ∨ k = kEkCt1Ack)) ∨
    (lab p = ct1Acknowledged ∧ (k = kEkCt1Ack ∨ k = kEk)) ∨ (lab p = keysSampled ∧ k = kCt1) ∨
    (lab p = ct1Received ∧ k = kCt2) ∨
    (lab p = ekReceivedCt1Sampled ∧ (k = kEkCt1Ack ∨ k = kCt1Ack)))
  lastParty := p
  lastKind := k
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- A message of an earlier epoch: no change. Its delivery is not checked. -/
action recv_older (p : party) (k : kind) {
  lastParty := p
  lastKind := k
  lastRel := older
  lastMac := absent
  lastKey := false
}

/-! ## Receive: the failures (`none`), with no state change -/

/- A message of a later epoch (`Deviation.futureEpochError`), except (13). Its delivery is not checked. -/
action err_future (p : party) (k : kind) (r : erel) {
  require r = later ∨ (r = next ∧ lab p ≠ ct2Sampled)
  lastParty := p
  lastKind := k
  lastRel := r
  lastMac := absent
  lastKey := false
}

/- A chunk that completes `hdr || mac` or `ct2 || mac`, whose MAC check fails in the code.
Veil does not compare MAC values: the action needs only a `good` MAC observation. -/
action err_mac (p : party) (k : kind) {
  let q := if p = pA then pB else pA
  require sent q k (ep p)
  require (lab p = ekSentCt1Received ∧ k = kCt2) ∨ (lab p = noHeaderReceived ∧ k = kHdr)
  lastParty := p
  lastKind := k
  lastRel := same
  lastMac := good
  lastKey := false
}

/- A chunk that completes `ek`, which does not match the header. -/
action err_ek (p : party) (k : kind) {
  let q := if p = pA then pB else pA
  require sent q k (ep p)
  require (lab p = ct1Sampled ∨ lab p = ct1Acknowledged) ∧ (k = kEk ∨ k = kEkCt1Ack)
  lastParty := p
  lastKind := k
  lastRel := same
  lastMac := absent
  lastKey := false
}

/- Both parties stay within one epoch of each other (a sanity property of the braid). -/
safety [epochs_close] ep P ≤ ep Q + 1

/- Bound for the explicit-state model checker. -/
state_constraint [small] ep pA ≤ 3 ∧ ep pB ≤ 3

#gen_spec

end SpqrBraid
