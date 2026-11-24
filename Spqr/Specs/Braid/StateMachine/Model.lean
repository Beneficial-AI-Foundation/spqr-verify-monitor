/-
Copyright (c) 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Lacramioara Astefanoaei
-/
module

public import Aeneas
public meta import Spqr.Auxiliary.SpecTags
public import Spqr.Specs.Braid.Deviations

/-! # An abstract ML-KEM Braid machine

The state machine of [ML-KEM Braid] §2.5 and §2.6, written over the values each state holds.
The primitives are parameters (`Prims`): the incremental KEM of §1.2, and the erasure code,
`MAC`, `PROTOCOL_INFO`, `ToBytes`, `KDF_AUTH` and `KDF_OK` of §2.2. The authenticator of §2.4 is
built from them. Where the code differs from §2.5 (`Deviation`, `Deviations.lean`), the machine
follows the code, and the arm names the deviation.

The steps `sendM` and `receiveM` are generic over the monad `M` of the primitives (`MPrims`).
The model's `send` and `receive` are `Id.run` of them over the total primitives `Prims`. A runtime
monitor runs them in `Option` over partial primitives (`PartialModel.lean`).

`send` takes the randomness that §1.2 gives `KeyGen` and `Encaps1`. `receive` returns `none` for
a failure of §2.5 (`FAIL` in `VfyHdr` or `VfyCt`, the `ek` integrity error) and for a message
from a later epoch, except a message of the next epoch in `Ct2Sampled` (transition (13)).
`Step` is one step of one party, and `Run` is a sequence of steps.

**Source**: ML-KEM Braid Rev. 1, §1.2, §2.2–§2.6 -/

@[expose] public section

open Aeneas Aeneas.Std Result

namespace BraidModel

/-- A byte string. The model gives bytes no structure beyond concatenation and splitting. -/
abbrev Bytes := List Std.U8

/-- The bytes of an ASCII string, for the labels of §2.4. -/
def ascii (s : String) : Bytes := s.toList.map (fun c => ⟨BitVec.ofNat 8 c.toNat⟩)

/-- The primitives that ML-KEM Braid takes as parameters: the erasure code of §2.2, the
incremental KEM of §1.2 with its constants, and `MAC`, `PROTOCOL_INFO`, `ToBytes`, `KDF_AUTH`
and `KDF_OK` of §2.2. `Enc`, `Dec` and `Chunk` are the types of encoders, decoders and
codewords. `message d` is `d.message()` when `d.has_message()` holds, and `none` otherwise.

The functions other than `encode`, `decoderNew`, `addChunk` and `toBytes` return their value in
the monad `M`; these four functions and the constants are total. The model takes `M = Id`
(`Prims`). A runtime monitor takes `M = Option` (`OPrims`, `PartialModel.lean`): there a
primitive returns `none` at an argument where its value is not known. -/
structure MPrims (M : Type → Type) (Enc Dec Chunk : Type) where
  /-- `Encode(byte_array) → encoder` -/
  encode : Bytes → Enc
  /-- `encoder.next_chunk()`, with the encoder after the call -/
  nextChunk : Enc → M (Chunk × Enc)
  /-- `Decoder.new(message_size)` -/
  decoderNew : Nat → Dec
  /-- `decoder.add_chunk(chunk)`, with the decoder after the call -/
  addChunk : Dec → Chunk → Dec
  /-- `decoder.message()` when `decoder.has_message()` holds, and `none` otherwise -/
  message : Dec → M (Option Bytes)
  /-- `KeyGen(randomness) → (dk, ek_header, ek_vector)` -/
  keyGen : Bytes → M (Bytes × Bytes × Bytes)
  /-- `Encaps1(ek_header, randomness) → (encaps_secret, ct1, shared_secret)` -/
  encaps1 : Bytes → Bytes → M (Bytes × Bytes × Bytes)
  /-- `Encaps2(encaps_secret, ek_header, ek_vector) → ct2` -/
  encaps2 : Bytes → Bytes → Bytes → M Bytes
  /-- `Decaps(dk, ct1, ct2) → shared_secret` -/
  decaps : Bytes → Bytes → Bytes → M Bytes
  /-- The integrity check of `ek_vector` against `ek_header`. In §1.2.1 and §2.5 it is
  `SHA3-256(ek_seed || ek_vector) = hek`. -/
  ekMatches : Bytes → Bytes → M Bool
  /-- `KEM.HEADER_SIZE` -/
  headerSize : Nat
  /-- `KEM.EK_SIZE` -/
  ekSize : Nat
  /-- `KEM.CT1_SIZE` -/
  ct1Size : Nat
  /-- `KEM.CT2_SIZE` -/
  ct2Size : Nat
  /-- `MAC_SIZE` -/
  macSize : Nat
  /-- `MAC(mac_key, msg)` -/
  mac : Bytes → Bytes → M Bytes
  /-- `PROTOCOL_INFO` -/
  protocolInfo : Bytes
  /-- `ToBytes(epoch)` -/
  toBytes : Nat → Bytes
  /-- `KDF_AUTH(root_key, update_key, epoch)`, 64 bytes. -/
  kdfAuth : Bytes → Bytes → Nat → M Bytes
  /-- `KDF_OK(shared_secret, epoch)`, 32 bytes. -/
  kdfOk : Bytes → Nat → M Bytes

/-- The primitives of the model: every primitive is a total function. -/
abbrev Prims := MPrims Id

variable {M : Type → Type} [Monad M] {Enc Dec Chunk : Type}

/-- The Ratcheted Authenticator state of §2.4. -/
structure Auth where
  /-- `root_key` -/
  rootKey : Bytes
  /-- `mac_key` -/
  macKey : Bytes

/-- `Authenticator.Update` (§2.4): the 64 bytes of `KDF_AUTH` are the new `root_key` and
`mac_key`. -/
def Auth.updateM (P : MPrims M Enc Dec Chunk) (a : Auth) (epoch : Nat) (key : Bytes) :
    M Auth := do
  let out ← P.kdfAuth a.rootKey key epoch
  pure { rootKey := out.take 32, macKey := out.drop 32 }

/-- `Authenticator.Init` (§2.4): a zero `root_key`, then `Update`. -/
def Auth.initM (P : MPrims M Enc Dec Chunk) (epoch : Nat) (key : Bytes) : M Auth :=
  Auth.updateM P { rootKey := List.replicate 32 0#u8, macKey := [] } epoch key

/-- `Authenticator.MacHdr` (§2.4). -/
def Auth.macHdrM (P : MPrims M Enc Dec Chunk) (a : Auth) (epoch : Nat) (hdr : Bytes) :
    M Bytes :=
  P.mac a.macKey (P.protocolInfo ++ ascii ":ekheader" ++ P.toBytes epoch ++ hdr)

/-- `Authenticator.MacCt` (§2.4). -/
def Auth.macCtM (P : MPrims M Enc Dec Chunk) (a : Auth) (epoch : Nat) (ct : Bytes) :
    M Bytes :=
  P.mac a.macKey (P.protocolInfo ++ ascii ":ciphertext" ++ P.toBytes epoch ++ ct)

/-- `Auth.updateM` over `Prims`. -/
def Auth.update (P : Prims Enc Dec Chunk) (a : Auth) (epoch : Nat) (key : Bytes) : Auth :=
  Id.run (Auth.updateM P a epoch key)

/-- `Auth.initM` over `Prims`. -/
def Auth.init (P : Prims Enc Dec Chunk) (epoch : Nat) (key : Bytes) : Auth :=
  Id.run (Auth.initM P epoch key)

/-- `Auth.macHdrM` over `Prims`. -/
def Auth.macHdr (P : Prims Enc Dec Chunk) (a : Auth) (epoch : Nat) (hdr : Bytes) : Bytes :=
  Id.run (Auth.macHdrM P a epoch hdr)

/-- `Auth.macCtM` over `Prims`. -/
def Auth.macCt (P : Prims Enc Dec Chunk) (a : Auth) (epoch : Nat) (ct : Bytes) : Bytes :=
  Id.run (Auth.macCtM P a epoch ct)

/-- The eleven states of §2.5 with the variables each one holds. `hdr` is the §1.2
`ek_header`, which for ML-KEM is `ek_seed || hek`. -/
inductive State (Enc Dec : Type) where
  | keysUnsampled (epoch : Nat) (auth : Auth)
  | keysSampled (epoch : Nat) (auth : Auth) (dk hdr ek : Bytes) (headerEncoder : Enc)
  | headerSent (epoch : Nat) (auth : Auth) (dk : Bytes) (ct1Decoder : Dec) (ekEncoder : Enc)
  | ct1Received (epoch : Nat) (auth : Auth) (dk ct1 : Bytes) (ekEncoder : Enc)
  | ekSentCt1Received (epoch : Nat) (auth : Auth) (dk ct1 : Bytes) (ct2Decoder : Dec)
  | noHeaderReceived (epoch : Nat) (auth : Auth) (headerDecoder : Dec)
  | headerReceived (epoch : Nat) (auth : Auth) (hdr : Bytes) (ekDecoder : Dec)
  | ct1Sampled (epoch : Nat) (auth : Auth) (hdr encapsSecret ct1 : Bytes) (ct1Encoder : Enc)
      (ekDecoder : Dec)
  | ekReceivedCt1Sampled (epoch : Nat) (auth : Auth) (encapsSecret ct1 hdr ek : Bytes)
      (ct1Encoder : Enc)
  | ct1Acknowledged (epoch : Nat) (auth : Auth) (hdr encapsSecret ct1 : Bytes) (ekDecoder : Dec)
  | ct2Sampled (epoch : Nat) (auth : Auth) (ct2Encoder : Enc)

/-- The epoch every state holds. -/
def State.epoch : State Enc Dec → Nat
  | .keysUnsampled e .. | .keysSampled e .. | .headerSent e .. | .ct1Received e ..
  | .ekSentCt1Received e .. | .noHeaderReceived e .. | .headerReceived e ..
  | .ct1Sampled e .. | .ekReceivedCt1Sampled e .. | .ct1Acknowledged e .. | .ct2Sampled e .. => e

/-- The message types of §2.3. `ct1Ack` has no payload. -/
inductive Payload (Chunk : Type) where
  | none
  | hdr (c : Chunk)
  | ek (c : Chunk)
  | ekCt1Ack (c : Chunk)
  | ct1Ack
  | ct1 (c : Chunk)
  | ct2 (c : Chunk)

/-- A message of §2.3. -/
structure Msg (Chunk : Type) where
  /-- The epoch being negotiated. -/
  epoch : Nat
  /-- The message type and its chunk. -/
  payload : Payload Chunk

/-- An output key `(epoch, shared_secret)`. -/
abbrev Key := Nat × Bytes

/-- The `ct2` encoder of transitions (9), (11) and (12): `Encode(ct2 || mac)` with
`ct2 = KEM.Encaps2(encaps_secret, ek_header, ek_vector)` and `mac = MacCt(epoch, ct1 || ct2)`. -/
def ct2EncoderM (P : MPrims M Enc Dec Chunk) (epoch : Nat) (auth : Auth)
    (encapsSecret ct1 hdr ek : Bytes) : M Enc := do
  let ct2 ← P.encaps2 encapsSecret hdr ek
  let t ← Auth.macCtM P auth epoch (ct1 ++ ct2)
  pure (P.encode (ct2 ++ t))

/-- `ct2EncoderM` over `Prims`. -/
def ct2Encoder (P : Prims Enc Dec Chunk) (epoch : Nat) (auth : Auth)
    (encapsSecret ct1 hdr ek : Bytes) : Enc :=
  Id.run (ct2EncoderM P epoch auth encapsSecret ct1 hdr ek)

/-- `Send()` of §2.5 with `Deviation.ct1AckAccepted` applied. `r` is the randomness that
`KeyGen` (transition (1)) and `Encaps1` (transition (7)) take in §1.2; the other states ignore
it. The result is the new state, the message and the output key. -/
@[braid_deviation Deviation.ct1AckAccepted]
def sendM (P : MPrims M Enc Dec Chunk) (σ : State Enc Dec) (r : Bytes) :
    M (State Enc Dec × Msg Chunk × Option Key) :=
  match σ with
  | .keysUnsampled e a => do
    let (dk, hdr, ek) ← P.keyGen r
    let t ← Auth.macHdrM P a e hdr
    let (c, enc) ← P.nextChunk (P.encode (hdr ++ t))
    pure (.keysSampled e a dk hdr ek enc, ⟨e, .hdr c⟩, none)                           -- (1)
  | .keysSampled e a dk hdr ek enc => do
    let (c, enc') ← P.nextChunk enc
    pure (.keysSampled e a dk hdr ek enc', ⟨e, .hdr c⟩, none)
  | .headerSent e a dk d enc => do
    let (c, enc') ← P.nextChunk enc
    pure (.headerSent e a dk d enc', ⟨e, .ek c⟩, none)
  | .ct1Received e a dk ct1 enc => do
    let (c, enc') ← P.nextChunk enc
    pure (.ct1Received e a dk ct1 enc', ⟨e, .ekCt1Ack c⟩, none)
  | .ekSentCt1Received e a dk ct1 d =>
    -- Deviation.ct1AckAccepted: §2.5 sends a message of type `None`.
    pure (.ekSentCt1Received e a dk ct1 d, ⟨e, .ct1Ack⟩, none)
  | .noHeaderReceived e a d => pure (.noHeaderReceived e a d, ⟨e, .none⟩, none)
  | .headerReceived e a hdr d => do
    let (es, ct1, ss₀) ← P.encaps1 hdr r
    let ss ← P.kdfOk ss₀ e
    let a' ← Auth.updateM P a e ss
    let (c, enc) ← P.nextChunk (P.encode ct1)
    pure (.ct1Sampled e a' hdr es ct1 enc d, ⟨e, .ct1 c⟩, some (e, ss))                -- (7)
  | .ct1Sampled e a hdr es ct1 enc d => do
    let (c, enc') ← P.nextChunk enc
    pure (.ct1Sampled e a hdr es ct1 enc' d, ⟨e, .ct1 c⟩, none)
  | .ekReceivedCt1Sampled e a es ct1 hdr ek enc => do
    let (c, enc') ← P.nextChunk enc
    pure (.ekReceivedCt1Sampled e a es ct1 hdr ek enc', ⟨e, .ct1 c⟩, none)
  | .ct1Acknowledged e a hdr es ct1 d => pure (.ct1Acknowledged e a hdr es ct1 d, ⟨e, .none⟩, none)
  | .ct2Sampled e a enc => do
    let (c, enc') ← P.nextChunk enc
    pure (.ct2Sampled e a enc', ⟨e, .ct2 c⟩, none)

/-- `sendM` over `Prims`. -/
def send (P : Prims Enc Dec Chunk) (σ : State Enc Dec) (r : Bytes) :
    State Enc Dec × Msg Chunk × Option Key :=
  Id.run (sendM P σ r)

/-- The arms of `receiveEqM` that add an `ek` chunk in `Ct1Sampled` or `Ct1Acknowledged` and
then may reach `Ct2Sampled` (transitions (8), (9) and (11)). With the decoder `d'` that has the
new chunk: no message gives `Ct1Acknowledged` with `d'`; a message `ek` that matches the header
gives `Ct2Sampled`; any other message is a failure. -/
def ekDoneM (P : MPrims M Enc Dec Chunk) (e : Nat) (a : Auth) (hdr es ct1 : Bytes) (d' : Dec) :
    M (Option (State Enc Dec × Option Key)) := do
  match ← P.message d' with
  | none => pure (some (.ct1Acknowledged e a hdr es ct1 d', none))
  | some ek =>
    if ← P.ekMatches hdr ek then
      let enc ← ct2EncoderM P e a es ct1 hdr ek
      pure (some (.ct2Sampled e a enc, none))
    else pure none

/-- `Receive()` of §2.5 for a message from the state's own epoch, with `Deviation.ct1AckAccepted`
and `Deviation.lateEkChunk` applied. The result `none` inside `M` is a failure of §2.5 (`FAIL` in
`VfyHdr` / `VfyCt`, or the `ek` integrity error). A message the state does not act on leaves it
unchanged. -/
@[braid_deviation Deviation.ct1AckAccepted Deviation.lateEkChunk]
def receiveEqM (P : MPrims M Enc Dec Chunk) : State Enc Dec → Payload Chunk →
    M (Option (State Enc Dec × Option Key))
  | .keysSampled e a dk _ ek _, .ct1 c =>
    pure (some (.headerSent e a dk (P.addChunk (P.decoderNew P.ct1Size) c) (P.encode ek),
      none))                                                                              -- (2)
  | .headerSent e a dk d enc, .ct1 c => do
    let d' := P.addChunk d c
    match ← P.message d' with
    | some ct1 => pure (some (.ct1Received e a dk ct1 enc, none))                         -- (3)
    | none => pure (some (.headerSent e a dk d' enc, none))
  | .ct1Received e a dk ct1 _, .ct2 c =>
    pure (some (.ekSentCt1Received e a dk ct1
      (P.addChunk (P.decoderNew (P.ct2Size + P.macSize)) c), none))                        -- (4)
  | .ekSentCt1Received e a dk ct1 d, .ct2 c => do
    let d' := P.addChunk d c
    match ← P.message d' with
    | none => pure (some (.ekSentCt1Received e a dk ct1 d', none))
    | some m =>
      let ct2 := m.take P.ct2Size
      let ss₀ ← P.decaps dk ct1 ct2
      let ss ← P.kdfOk ss₀ e
      let a' ← Auth.updateM P a e ss
      let t ← Auth.macCtM P a' e (ct1 ++ ct2)
      if m.drop P.ct2Size = t then
        pure (some (.noHeaderReceived (e + 1) a' (P.decoderNew (P.headerSize + P.macSize)),
          some (e, ss)))                                                                  -- (5)
      else pure none
  | .noHeaderReceived e a d, .hdr c => do
    let d' := P.addChunk d c
    match ← P.message d' with
    | none => pure (some (.noHeaderReceived e a d', none))
    | some m =>
      let hdr := m.take P.headerSize
      let t ← Auth.macHdrM P a e hdr
      if m.drop P.headerSize = t then
        pure (some (.headerReceived e a hdr (P.decoderNew P.ekSize), none))               -- (6)
      else pure none
  | .ct1Sampled e a hdr es ct1 enc d, .ek c => do
    let d' := P.addChunk d c
    match ← P.message d' with
    | none => pure (some (.ct1Sampled e a hdr es ct1 enc d', none))
    | some ek =>
      if ← P.ekMatches hdr ek then
        pure (some (.ekReceivedCt1Sampled e a es ct1 hdr ek enc, none))                   -- (10)
      else pure none
  | .ct1Sampled e a hdr es ct1 _ d, .ekCt1Ack c =>
    -- (8), (9)
    ekDoneM P e a hdr es ct1 (P.addChunk d c)
  | .ekReceivedCt1Sampled e a es ct1 hdr ek _, .ekCt1Ack _ => do
    let enc ← ct2EncoderM P e a es ct1 hdr ek
    pure (some (.ct2Sampled e a enc, none))                                               -- (12)
  | .ekReceivedCt1Sampled e a es ct1 hdr ek _, .ct1Ack => do
    -- Deviation.ct1AckAccepted: §2.5 acts only on `EkCt1Ack` here.
    let enc ← ct2EncoderM P e a es ct1 hdr ek
    pure (some (.ct2Sampled e a enc, none))                                               -- (12)
  | .ct1Acknowledged e a hdr es ct1 d, .ekCt1Ack c =>
    -- (11)
    ekDoneM P e a hdr es ct1 (P.addChunk d c)
  | .ct1Acknowledged e a hdr es ct1 d, .ek c =>
    -- Deviation.lateEkChunk: §2.5 acts only on `EkCt1Ack` here. (11)
    ekDoneM P e a hdr es ct1 (P.addChunk d c)
  | σ, _ => pure (some (σ, none))

/-- `receiveEqM` over `Prims`. -/
def receiveEq (P : Prims Enc Dec Chunk) (σ : State Enc Dec) (p : Payload Chunk) :
    Option (State Enc Dec × Option Key) :=
  Id.run (receiveEqM P σ p)

/-- `Receive()` of §2.5 with `Deviation.futureEpochError` applied: a message from a later epoch is
a failure, except in `Ct2Sampled` at `epoch + 1` (transition (13)). A message from an earlier
epoch leaves the state unchanged. -/
@[braid_deviation Deviation.futureEpochError]
def receiveM (P : MPrims M Enc Dec Chunk) (σ : State Enc Dec) (m : Msg Chunk) :
    M (Option (State Enc Dec × Option Key)) :=
  match σ with
  | .ct2Sampled e a _ =>
    if m.epoch = e + 1 then pure (some (.keysUnsampled (e + 1) a, none))                  -- (13)
    else if m.epoch > e then pure none
    else pure (some (σ, none))
  | _ =>
    if m.epoch > σ.epoch then pure none
    else if m.epoch < σ.epoch then pure (some (σ, none))
    else receiveEqM P σ m.payload

/-- `receiveM` over `Prims`. -/
def receive (P : Prims Enc Dec Chunk) (σ : State Enc Dec) (m : Msg Chunk) :
    Option (State Enc Dec × Option Key) :=
  Id.run (receiveM P σ m)

/-- `InitAlice` (§2.6). -/
def initAliceM (P : MPrims M Enc Dec Chunk) (sharedSecret : Bytes) : M (State Enc Dec) := do
  let a ← Auth.initM P 1 sharedSecret
  pure (.keysUnsampled 1 a)

/-- `InitBob` (§2.6). -/
def initBobM (P : MPrims M Enc Dec Chunk) (sharedSecret : Bytes) : M (State Enc Dec) := do
  let a ← Auth.initM P 1 sharedSecret
  pure (.noHeaderReceived 1 a (P.decoderNew (P.headerSize + P.macSize)))

/-- `initAliceM` over `Prims`. -/
def initAlice (P : Prims Enc Dec Chunk) (sharedSecret : Bytes) : State Enc Dec :=
  Id.run (initAliceM P sharedSecret)

/-- `initBobM` over `Prims`. -/
def initBob (P : Prims Enc Dec Chunk) (sharedSecret : Bytes) : State Enc Dec :=
  Id.run (initBobM P sharedSecret)

section Run

/-! The total functions are `Id.run` of the generic ones. To unfold a total function, give
`simp` its definition, the definition of the generic function, `id_run`, `id_bind` and `id_pure`.
The `_eq` lemmas fold the helper functions back into their total versions. -/

/-- `Id.run` is the identity. -/
theorem id_run {α : Type} (x : Id α) : Id.run x = x := rfl

/-- `bind` in `Id` is application. -/
theorem id_bind {α β : Type} (x : Id α) (f : α → Id β) : x >>= f = f x := rfl

/-- `pure` in `Id` is the identity. -/
theorem id_pure {α : Type} (a : α) : (pure a : Id α) = a := rfl

variable {P : Prims Enc Dec Chunk}

/-- `Auth.updateM` in `Id` is `Auth.update`. -/
theorem Auth.updateM_eq (a : Auth) (e : Nat) (k : Bytes) :
    Auth.updateM P a e k = Auth.update P a e k := rfl

/-- `Auth.initM` in `Id` is `Auth.init`. -/
theorem Auth.initM_eq (e : Nat) (k : Bytes) : Auth.initM P e k = Auth.init P e k := rfl

/-- `Auth.macHdrM` in `Id` is `Auth.macHdr`. -/
theorem Auth.macHdrM_eq (a : Auth) (e : Nat) (hdr : Bytes) :
    Auth.macHdrM P a e hdr = Auth.macHdr P a e hdr := rfl

/-- `Auth.macCtM` in `Id` is `Auth.macCt`. -/
theorem Auth.macCtM_eq (a : Auth) (e : Nat) (ct : Bytes) :
    Auth.macCtM P a e ct = Auth.macCt P a e ct := rfl

/-- `ct2EncoderM` in `Id` is `ct2Encoder`. -/
theorem ct2EncoderM_eq (e : Nat) (a : Auth) (es ct1 hdr ek : Bytes) :
    ct2EncoderM P e a es ct1 hdr ek = ct2Encoder P e a es ct1 hdr ek := rfl

/-- `receiveEqM` in `Id` is `receiveEq`. -/
theorem receiveEqM_eq (σ : State Enc Dec) (p : Payload Chunk) :
    receiveEqM P σ p = receiveEq P σ p := rfl

end Run

/-- One step of one party: a `Send()` with some randomness, or a `Receive()` of some message
that does not fail. -/
inductive Step (P : Prims Enc Dec Chunk) : State Enc Dec → State Enc Dec → Option Key → Prop
  | send (σ : State Enc Dec) (r : Bytes) : Step P σ (send P σ r).1 (send P σ r).2.2
  | recv (σ σ' : State Enc Dec) (m : Msg Chunk) (k : Option Key) :
      receive P σ m = some (σ', k) → Step P σ σ' k

/-- A run of one party from `σ` to `σ'` that emits the keys `ks`, in order. -/
inductive Run (P : Prims Enc Dec Chunk) : State Enc Dec → State Enc Dec → List Key → Prop
  | nil (σ : State Enc Dec) : Run P σ σ []
  | cons {σ σ₁ σ₂ : State Enc Dec} {k : Option Key} {ks : List Key} :
      Step P σ σ₁ k → Run P σ₁ σ₂ ks → Run P σ σ₂ (k.toList ++ ks)

end BraidModel
