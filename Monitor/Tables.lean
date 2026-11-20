/-
Copyright (c) 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Lacramioara Astefanoaei
-/
import Spqr.Specs.Braid.StateMachine.Monitor
import Std.Data.HashMap

/-! # The monitor's partial primitives

The partial primitives `Tables.prims` that the monitor replays with. The erasure code is
represented by its inputs: an encoder is its message and the number of chunks it emitted, a
decoder is its size and the chunks added to it. Systematic chunks are computed. Parity chunks,
decoder results and the cryptographic primitives are looked up in tables: the monitor fills
them from the logged calls and, for parity chunks, from the sent messages. `kdfAuth` and `kdfOk`
look up the logged HKDF calls at the salt, key and info that `CodeAgrees.kdfAuth` and
`CodeAgrees.kdfOk` (`Relation.lean`) fix. The code's `encaps2` takes no header, so `encaps2`
ignores its header argument. -/

open Aeneas Aeneas.Std BraidModel

namespace Monitor

instance : Hashable Std.U8 := ⟨fun x => hash x.val⟩

/-- A codeword chunk: its index and its data bytes. -/
structure MChunk where
  index : Nat
  data : Bytes
  deriving DecidableEq, Hashable, Inhabited

/-- An encoder: its message and the number of chunks emitted so far. -/
abbrev MEnc := Bytes × Nat

/-- A decoder: its message size in bytes, the chunks added to it, newest first, and a hash of
both that `addChunk` extends. Adding a chunk and hashing a decoder take constant time. -/
structure MDec where
  size : Nat
  chunks : List MChunk
  hashv : UInt64
  deriving DecidableEq, Inhabited

instance : Hashable MDec := ⟨MDec.hashv⟩

/-- The decoder of a message of `n` bytes with no chunks. -/
def MDec.new (n : Nat) : MDec := ⟨n, [], hash n⟩

/-- Add a chunk to a decoder. -/
def MDec.addChunk (d : MDec) (c : MChunk) : MDec :=
  ⟨d.size, c :: d.chunks, mixHash d.hashv (hash c)⟩

/-- The chunk of a payload, if it has one. -/
def chunkOf : Payload MChunk → Option MChunk
  | .hdr c | .ek c | .ekCt1Ack c | .ct1 c | .ct2 c => some c
  | .none | .ct1Ack => none

/-- The byte of a natural number below 256. -/
def byte (n : Nat) : Std.U8 := ⟨BitVec.ofNat 8 n⟩

/-- `n` as 8 big-endian bytes, as `u64::to_be_bytes`. -/
def be64 (n : Nat) : Bytes := (List.range 8).reverse.map fun i => byte (n / 256 ^ i % 256)

/-- `PROTOCOL_INFO` of the code. -/
def protocolInfo : Bytes := ascii "Signal_PQCKA_V1_MLKEM768"

/-- The HKDF info label of `Authenticator::update` (`updateLabel` in the specs). -/
def updateLabel : Bytes := ascii "Signal_PQCKA_V1_MLKEM768:Authenticator Update"

/-- The HKDF info label of the SCKA key (`sckaKeyLabel` in the specs). -/
def sckaKeyLabel : Bytes := ascii "Signal_PQCKA_V1_MLKEM768:SCKA Key"

/-- The 32-byte zero salt of the code's HKDF calls. -/
def zeroSalt : Bytes := List.replicate 32 (byte 0)

/-- The systematic chunk `i` of the message `m`: its bytes `[32i, 32i + 32)`. -/
def systematicChunk (m : Bytes) (i : Nat) : MChunk := ⟨i, (m.drop (32 * i)).take 32⟩

open Std in
/-- Primitive values keyed by their arguments. -/
structure Tables where
  /-- `hkdf(salt, ikm, info, len)` -/
  hkdf : HashMap (Bytes × Bytes × Bytes × Nat) Bytes := {}
  /-- `hmac(key, data)` -/
  hmac : HashMap (Bytes × Bytes) Bytes := {}
  /-- `generate`: seed to `(dk, hdr, ek)` -/
  keyGen : HashMap Bytes (Bytes × Bytes × Bytes) := {}
  /-- `encaps1`: `(hdr, randomness)` to `(es, ct1, ss)` -/
  encaps1 : HashMap (Bytes × Bytes) (Bytes × Bytes × Bytes) := {}
  /-- `encaps2`: `(es, ek)` to `ct2` -/
  encaps2 : HashMap (Bytes × Bytes) Bytes := {}
  /-- `decaps`: `(dk, ct1, ct2)` to `ss` -/
  decaps : HashMap (Bytes × Bytes × Bytes) Bytes := {}
  /-- `ek_matches_header`: `(hdr, ek)` to the result -/
  ekMatches : HashMap (Bytes × Bytes) Bool := {}
  /-- decoder results, keyed by the decoder -/
  message : HashMap MDec (Option Bytes) := {}
  /-- parity chunks, keyed by the encoder -/
  parity : HashMap MEnc MChunk := {}
  deriving Inhabited

/-- The partial primitives of the tables. -/
def Tables.prims (T : Tables) : OPrims MEnc MDec MChunk where
  encode m := (m, 0)
  nextChunk enc :=
    let c := if enc.2 < enc.1.length / 32 then some (systematicChunk enc.1 enc.2)
      else T.parity[enc]?
    c.map fun c => (c, (enc.1, enc.2 + 1))
  decoderNew := MDec.new
  addChunk := MDec.addChunk
  message d := T.message[d]?
  keyGen r := T.keyGen[r]?
  encaps1 hdr r := T.encaps1[(hdr, r)]?
  encaps2 es _ ek := T.encaps2[(es, ek)]?
  decaps dk ct1 ct2 := T.decaps[(dk, ct1, ct2)]?
  ekMatches hdr ek := T.ekMatches[(hdr, ek)]?
  headerSize := 64
  ekSize := 1152
  ct1Size := 960
  ct2Size := 128
  macSize := 32
  mac k d := T.hmac[(k, d)]?
  protocolInfo := protocolInfo
  toBytes := be64
  kdfAuth rk k e := T.hkdf[(zeroSalt, rk ++ k, updateLabel ++ be64 e, 64)]?
  kdfOk ss e := T.hkdf[(zeroSalt, ss, sckaKeyLabel ++ be64 e, 32)]?

end Monitor
