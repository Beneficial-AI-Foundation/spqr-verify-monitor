/-
Copyright (c) 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Lacramioara Astefanoaei
-/
module

public import Spqr.Specs.Braid.StateMachine.Model

/-! # The ML-KEM Braid machine over partially known primitives

A runtime monitor knows the primitives only at the arguments where it saw the code call them.
`OPrims` holds such partial primitives: `MPrims` of `Model.lean` in the monad `Option`, where a
primitive learned from calls returns `none` where no call was seen. Over `OPrims`, `sendM`,
`receiveM`, `initAliceM` and `initBobM` of `Model.lean` return `none` when the step needs a value
that the partial primitives do not have.

`Agrees P Q` states that the total primitives `P` extend the partial primitives `Q`. Each
`_sound` theorem states that a result of the computation over `Q` is the result of the same
computation over every `P` that extends `Q`.

**Source**: ML-KEM Braid Rev. 1, §1.2, §2.2–§2.6 -/

@[expose] public section

open Aeneas Aeneas.Std

namespace BraidModel

/-- Partial primitives: `MPrims` in the monad `Option`. `nextChunk`, `message`, the KEM,
`ekMatches`, `MAC`, `KDF_AUTH` and `KDF_OK` return `none` at an argument where the value is not
known. -/
abbrev OPrims := MPrims Option

variable {Enc Dec Chunk : Type}

/-- `P` extends `Q`: the fields that are total in `Q` are equal, and wherever a field of `Q`
returns `some v`, the field of `P` returns `v`. -/
structure Agrees (P : Prims Enc Dec Chunk) (Q : OPrims Enc Dec Chunk) : Prop where
  encode : P.encode = Q.encode
  nextChunk : ∀ x v, Q.nextChunk x = some v → P.nextChunk x = v
  decoderNew : P.decoderNew = Q.decoderNew
  addChunk : P.addChunk = Q.addChunk
  message : ∀ d v, Q.message d = some v → P.message d = v
  keyGen : ∀ r v, Q.keyGen r = some v → P.keyGen r = v
  encaps1 : ∀ hdr r v, Q.encaps1 hdr r = some v → P.encaps1 hdr r = v
  encaps2 : ∀ es hdr ek v, Q.encaps2 es hdr ek = some v → P.encaps2 es hdr ek = v
  decaps : ∀ dk ct1 ct2 v, Q.decaps dk ct1 ct2 = some v → P.decaps dk ct1 ct2 = v
  ekMatches : ∀ hdr ek v, Q.ekMatches hdr ek = some v → P.ekMatches hdr ek = v
  headerSize : P.headerSize = Q.headerSize
  ekSize : P.ekSize = Q.ekSize
  ct1Size : P.ct1Size = Q.ct1Size
  ct2Size : P.ct2Size = Q.ct2Size
  macSize : P.macSize = Q.macSize
  mac : ∀ k d v, Q.mac k d = some v → P.mac k d = v
  protocolInfo : P.protocolInfo = Q.protocolInfo
  toBytes : P.toBytes = Q.toBytes
  kdfAuth : ∀ rk k e v, Q.kdfAuth rk k e = some v → P.kdfAuth rk k e = v
  kdfOk : ∀ ss e v, Q.kdfOk ss e = some v → P.kdfOk ss e = v

section Soundness

variable {P : Prims Enc Dec Chunk} {Q : OPrims Enc Dec Chunk}

/-- If `Auth.updateM Q a e k` returns `a'`, then every `P` that extends `Q` gives
`Auth.update P a e k = a'`. -/
theorem Auth.updateM_sound (hA : Agrees P Q) {a a' : Auth} {e : Nat} {k : Bytes}
    (h : Auth.updateM Q a e k = some a') : Auth.update P a e k = a' := by
  simp only [Auth.updateM, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
    Option.some.injEq] at h
  obtain ⟨out, hout, rfl⟩ := h
  simp only [Auth.update, Auth.updateM, id_run, id_bind, id_pure, hA.kdfAuth _ _ _ _ hout]

/-- If `Auth.initM Q e k` returns `a`, then every `P` that extends `Q` gives
`Auth.init P e k = a`. -/
theorem Auth.initM_sound (hA : Agrees P Q) {a : Auth} {e : Nat} {k : Bytes}
    (h : Auth.initM Q e k = some a) : Auth.init P e k = a :=
  Auth.updateM_sound hA h

/-- If `Auth.macHdrM Q a e hdr` returns `t`, then every `P` that extends `Q` gives
`Auth.macHdr P a e hdr = t`. -/
theorem Auth.macHdrM_sound (hA : Agrees P Q) {a : Auth} {e : Nat} {hdr t : Bytes}
    (h : Auth.macHdrM Q a e hdr = some t) : Auth.macHdr P a e hdr = t := by
  simp only [Auth.macHdrM] at h
  simp only [Auth.macHdr, Auth.macHdrM, hA.protocolInfo, hA.toBytes, hA.mac _ _ _ h]; rfl

/-- If `Auth.macCtM Q a e ct` returns `t`, then every `P` that extends `Q` gives
`Auth.macCt P a e ct = t`. -/
theorem Auth.macCtM_sound (hA : Agrees P Q) {a : Auth} {e : Nat} {ct t : Bytes}
    (h : Auth.macCtM Q a e ct = some t) : Auth.macCt P a e ct = t := by
  simp only [Auth.macCtM] at h
  simp only [Auth.macCt, Auth.macCtM, hA.protocolInfo, hA.toBytes, hA.mac _ _ _ h]; rfl

/-- If `ct2EncoderM Q e a es ct1 hdr ek` returns `enc`, then every `P` that extends `Q` gives
`ct2Encoder P e a es ct1 hdr ek = enc`. -/
theorem ct2EncoderM_sound (hA : Agrees P Q) {e : Nat} {a : Auth} {es ct1 hdr ek : Bytes}
    {enc : Enc} (h : ct2EncoderM Q e a es ct1 hdr ek = some enc) :
    ct2Encoder P e a es ct1 hdr ek = enc := by
  simp only [ct2EncoderM, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
    Option.some.injEq] at h
  obtain ⟨ct2, h2, t, ht, rfl⟩ := h
  simp only [ct2Encoder, ct2EncoderM, id_run, id_bind, id_pure, hA.encaps2 _ _ _ _ h2,
    Auth.macCtM_eq, Auth.macCtM_sound hA ht, hA.encode]

/-- If `sendM Q σ r` returns `x`, then every `P` that extends `Q` gives `send P σ r = x`. -/
theorem sendM_sound (hA : Agrees P Q) {σ : State Enc Dec} {r : Bytes}
    {x : State Enc Dec × Msg Chunk × Option Key} (h : sendM Q σ r = some x) :
    send P σ r = x := by
  cases σ <;> simp only [sendM, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
    Option.some.injEq] at h <;> simp only [send, sendM, id_run, id_bind, id_pure]
  case keysUnsampled e a =>
    obtain ⟨⟨dk, hdr, ek⟩, hkg, t, ht, ⟨c, enc⟩, hce, rfl⟩ := h
    simp only [hA.keyGen _ _ hkg, Auth.macHdrM_eq, Auth.macHdrM_sound hA ht, hA.encode,
      hA.nextChunk _ _ hce]
  case headerReceived e a hdr d =>
    obtain ⟨⟨es, ct1, ss₀⟩, hx, ss, hss, a', ha', ⟨c, enc⟩, hce, rfl⟩ := h
    simp only [hA.encaps1 _ _ _ hx, hA.kdfOk _ _ _ hss, Auth.updateM_eq,
      Auth.updateM_sound hA ha', hA.encode, hA.nextChunk _ _ hce]
  all_goals first
    | (subst h; rfl)
    | (obtain ⟨⟨c, enc⟩, hce, rfl⟩ := h; simp only [hA.nextChunk _ _ hce])

/-- If `ekDoneM Q e a hdr es ct1 d' stay` returns `x`, then every `P` that extends `Q` gives
`ekDoneM P e a hdr es ct1 d' stay = x`. -/
theorem ekDoneM_sound (hA : Agrees P Q) {e : Nat} {a : Auth} {hdr es ct1 : Bytes} {d' : Dec}
    {stay : Dec → State Enc Dec} {x : Option (State Enc Dec × Option Key)}
    (h : ekDoneM Q e a hdr es ct1 d' stay = some x) :
    Id.run (ekDoneM P e a hdr es ct1 d' stay) = x := by
  simp only [ekDoneM, Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨msg, hmsg, h⟩ := h
  simp only [ekDoneM, id_run, id_bind, id_pure, hA.message _ _ hmsg]
  cases msg with
  | none => simpa only [Option.pure_def, Option.some.injEq] using h
  | some ek =>
    simp only [Option.bind_eq_some_iff] at h
    obtain ⟨ok, hok, h⟩ := h
    simp only [hA.ekMatches _ _ _ hok]
    cases ok with
    | false =>
      simpa only [Bool.false_eq_true, ↓reduceIte, Option.pure_def, Option.some.injEq] using h
    | true =>
      simp only [↓reduceIte, Option.bind_eq_some_iff, Option.pure_def, Option.some.injEq] at h
      obtain ⟨enc, henc, rfl⟩ := h
      simp only [↓reduceIte, ct2EncoderM_eq, ct2EncoderM_sound hA henc]

/-- If `receiveEqM Q σ p` returns `some x`, then every `P` that extends `Q` gives
`receiveEq P σ p = x`. -/
theorem receiveEqM_sound (hA : Agrees P Q) {σ : State Enc Dec} {p : Payload Chunk}
    {x : Option (State Enc Dec × Option Key)} (h : receiveEqM Q σ p = some x) :
    receiveEq P σ p = x := by
  unfold receiveEq
  cases σ <;> cases p <;>
    simp only [receiveEqM, id_run, id_bind, id_pure, Option.pure_def, Option.some.injEq,
      hA.addChunk, hA.decoderNew, hA.encode, hA.ct1Size, hA.ct2Size, hA.macSize,
      hA.headerSize, hA.ekSize] at h ⊢
  case headerSent.ct1 e a dk d enc c =>
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
    obtain ⟨msg, hmsg, h⟩ := h
    rw [hA.message _ _ hmsg]
    cases msg <;> simpa only [Option.pure_def, Option.some.injEq] using h
  case ekSentCt1Received.ct2 e a dk ct1 d c =>
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
    obtain ⟨msg, hmsg, h⟩ := h
    rw [hA.message _ _ hmsg]
    cases msg with
    | none => simpa only [Option.pure_def, Option.some.injEq] using h
    | some m =>
      simp only [Option.bind_eq_some_iff] at h
      obtain ⟨ss₀, hss₀, ss, hss, a', ha', t, ht, h⟩ := h
      simp only [hA.decaps _ _ _ _ hss₀, hA.kdfOk _ _ _ hss, Auth.updateM_eq,
        Auth.updateM_sound hA ha', Auth.macCtM_eq, Auth.macCtM_sound hA ht]
      split_ifs at h ⊢ <;> simpa only [Option.pure_def, Option.some.injEq] using h
  case noHeaderReceived.hdr e a d c =>
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
    obtain ⟨msg, hmsg, h⟩ := h
    rw [hA.message _ _ hmsg]
    cases msg with
    | none => simpa only [Option.pure_def, Option.some.injEq] using h
    | some m =>
      simp only [Option.bind_eq_some_iff] at h
      obtain ⟨t, ht, h⟩ := h
      simp only [Auth.macHdrM_eq, Auth.macHdrM_sound hA ht]
      split_ifs at h ⊢ <;> simpa only [Option.pure_def, Option.some.injEq] using h
  case ct1Sampled.ek e a hdr es ct1 enc d c =>
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
    obtain ⟨msg, hmsg, h⟩ := h
    rw [hA.message _ _ hmsg]
    cases msg with
    | none => simpa only [Option.pure_def, Option.some.injEq] using h
    | some ek =>
      simp only [Option.bind_eq_some_iff] at h
      obtain ⟨ok, hok, h⟩ := h
      simp only [hA.ekMatches _ _ _ hok]
      cases ok <;> simpa only [Bool.false_eq_true, ↓reduceIte, Option.pure_def,
        Option.some.injEq] using h
  case ct1Sampled.ekCt1Ack | ct1Acknowledged.ekCt1Ack | ct1Acknowledged.ek =>
    exact ekDoneM_sound hA h
  case ekReceivedCt1Sampled.ekCt1Ack | ekReceivedCt1Sampled.ct1Ack =>
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Option.some.injEq] at h
    obtain ⟨enc, henc, rfl⟩ := h
    rw [ct2EncoderM_eq, ct2EncoderM_sound hA henc]
  all_goals exact h

/-- If `receiveM Q σ m` returns `some x`, then every `P` that extends `Q` gives
`receive P σ m = x`. -/
theorem receiveM_sound (hA : Agrees P Q) {σ : State Enc Dec} {m : Msg Chunk}
    {x : Option (State Enc Dec × Option Key)} (h : receiveM Q σ m = some x) :
    receive P σ m = x := by
  by_cases hc : ∃ e a enc, σ = .ct2Sampled e a enc
  · obtain ⟨e, a, enc, rfl⟩ := hc
    simp only [receiveM, receive, id_run, id_pure, Option.pure_def] at h ⊢
    by_cases h1 : m.epoch = e + 1
    · simpa only [h1, ↓reduceIte, Option.some.injEq] using h
    · by_cases h2 : m.epoch > e
      · simpa only [h1, h2, ↓reduceIte, Option.some.injEq] using h
      · simpa only [h1, h2, ↓reduceIte, Option.some.injEq] using h
  · have hr : receive P σ m = if m.epoch > σ.epoch then none
        else if m.epoch < σ.epoch then some (σ, none) else receiveEq P σ m.payload := by
      cases σ <;> first | rfl | exact absurd ⟨_, _, _, rfl⟩ hc
    have hrO : receiveM Q σ m = if m.epoch > σ.epoch then some none
        else if m.epoch < σ.epoch then some (some (σ, none)) else receiveEqM Q σ m.payload := by
      cases σ <;> first | rfl | exact absurd ⟨_, _, _, rfl⟩ hc
    rw [hrO] at h
    rw [hr]
    by_cases h1 : m.epoch > σ.epoch
    · simpa only [h1, ↓reduceIte, Option.some.injEq] using h
    · by_cases h2 : m.epoch < σ.epoch
      · simpa only [h1, h2, ↓reduceIte, Option.some.injEq] using h
      · simp only [h1, h2, ↓reduceIte] at h ⊢
        exact receiveEqM_sound hA h

/-- If `initAliceM Q ss` returns `σ`, then every `P` that extends `Q` gives
`initAlice P ss = σ`. -/
theorem initAliceM_sound (hA : Agrees P Q) {ss : Bytes} {σ : State Enc Dec}
    (h : initAliceM Q ss = some σ) : initAlice P ss = σ := by
  simp only [initAliceM, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
    Option.some.injEq] at h
  obtain ⟨a, ha, rfl⟩ := h
  simp only [initAlice, initAliceM, id_run, id_bind, id_pure, Auth.initM_eq,
    Auth.initM_sound hA ha]

/-- If `initBobM Q ss` returns `σ`, then every `P` that extends `Q` gives
`initBob P ss = σ`. -/
theorem initBobM_sound (hA : Agrees P Q) {ss : Bytes} {σ : State Enc Dec}
    (h : initBobM Q ss = some σ) : initBob P ss = σ := by
  simp only [initBobM, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
    Option.some.injEq] at h
  obtain ⟨a, ha, rfl⟩ := h
  simp only [initBob, initBobM, id_run, id_bind, id_pure, Auth.initM_eq, Auth.initM_sound hA ha,
    hA.decoderNew, hA.headerSize, hA.macSize]

end Soundness

end BraidModel
