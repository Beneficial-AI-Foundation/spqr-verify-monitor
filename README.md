# Verify the Sparse Post-Quantum Ratchet (SPQR) using Lean

A project to formally verify [SparsePostQuantumRatchet](https://github.com/signalapp/SparsePostQuantumRatchet),
a Rust implementation of Signal's post-quantum secure ratchet protocol.

The verification uses [Lean 4](https://lean-lang.org) and relies on the Lean representation
of the Rust code produced by [Aeneas](https://github.com/AeneasVerif/aeneas).

Maintained by [The Beneficial AI Foundation](https://www.beneficialaifoundation.org/).

## About this fork

This fork of [Beneficial-AI-Foundation/SparsePostQuantumRatchet-verify](https://github.com/Beneficial-AI-Foundation/SparsePostQuantumRatchet-verify)
adds a runtime monitor for the SPQR tests. The Rust tests write an event log, and a Lean program
replays the events of each party through the Braid model.

### What the monitor checks that the proofs do not

The refinement proof `run_refines` is about the Lean translation of the code. In that
translation, ML-KEM is a hand-written model of FIPS 203 (`SrcTranslated/FunsExternal.lean`),
HMAC and HKDF are opaque, 26 translation patches change the Rust, and the SIMD field
multiplication is left out. The monitor takes the primitive values from the binary that runs. On
each recorded run, it checks that each logged step, with the logged primitive values, is the
model's step: the same message, key, state name and epoch. It does not check that a primitive
meets its specification, for example that libcrux computes FIPS 203. It checks only the steps
that the tests record.

### What is proved

`Spqr/Specs/Braid/StateMachine/PartialModel.lean` runs the model's steps `sendM` and `receiveM`
in `Option` over partial primitives `OPrims`, a table of the primitive values that one operation
logged. `Spqr/Specs/Braid/StateMachine/Monitor.lean` defines the checker `checkRun` and proves
`accepted_alice` and `accepted_bob`. Assume that the initialization of a party gives the state
`σ₀` and that `checkRun` accepts its logged steps from `σ₀`. Let `P` be a total primitive set that
extends the logged tables and has the same total fields. Then each observation is a model step
with `P` (`Explains`): a send or a successful receive gives the observed message or key, state
name and epoch, and a failed receive is a failed `Receive()` that leaves the state unchanged. And
the successful steps form a `BraidModel.Run` that emits the observed keys. The theorems have
no `sorry` and depend only on `propext`, `Classical.choice` and `Quot.sound`.

These parts are trusted, not proved: the hooks in `src/` and the event writer `src/monitor.rs`;
the executable in `Monitor/`, which builds the tables from the log and defines the total fields
(`Monitor/Tables.lean`); and the cross-party checks in `Monitor/Check.lean` (delivery, key
agreement and randomness reuse).

The hooks compile only with the cargo feature `monitor`. With the feature off, the expanded
library is identical to upstream `main` at `acd6e308`.

### Run the monitor

You need `cargo +1.99.1`, `protoc` and the Lean toolchain in `lean-toolchain`.

```bash
lake build Spqr.Specs.Braid.StateMachine.Monitor Spqr.Specs.Braid.StateMachine.Refinement Monitor
rm -rf /tmp/spqr-traces
SPQR_MONITOR_DIR=/tmp/spqr-traces cargo +1.99.1 test --features monitor
lake env lean --run Monitor/Main.lean /tmp/spqr-traces/*.jsonl
```

The monitor prints one line per party (`ACCEPTED`, or `REJECTED` with the reason and, when there
is one, the operation) and one line per cross-party check. When an epoch has a key from one party
only, a further line lists those epochs. It ends with `ALL CHECKS PASSED` (exit 0) or
`SOME CHECKS FAILED` (exit 1). A file that does not parse stops the program with an error and
no verdict. On the unmodified code, it accepts every party. A log has no end
marker, so an acceptance covers only the recorded steps. To run the demo mutants, read
[`mutants/README.md`](./mutants/README.md).

## Repository Structure

| Path | Contents |
|---|---|
| [`src/`](./src/) | Rust source of the SPQR crate at the pinned upstream commit (`aeneas-config.yml`), plus this fork's monitor hooks (feature `monitor`), `src/monitor.rs` and the tamper tests. With the feature off, the expanded library is identical to `acd6e308`. |
| [`translation-patches/`](./translation-patches/) | Rust changes needed for the translation, one function per patch, applied only while extracting (see [`scripts/README.md`](./scripts/README.md)). |
| [`SrcTranslated/`](./SrcTranslated/) | Aeneas-auto-generated Lean files (`Types.lean`, `Funs.lean`, never edited by hand) plus hand-written externals (`TypesExternal.lean`, `FunsExternal.lean`). |
| [`Spqr/Math/`](./Spqr/Math/) | Project-wide mathematical infrastructure, implemented in Lean. |
| [`Spqr/Specs/`](./Spqr/Specs/) | Lean spec theorem files: specs of individual Rust functions, organised to mirror the Rust module tree, and in `Braid/`, specs of ML-KEM Braid properties over runs of the state machine, organised by the Braid spec's sections. |
| [`aeneas-config.yml`](./aeneas-config.yml) | Aeneas extraction configuration. |
| [`scripts/`](./scripts/) | Project tooling scripts (extraction, diffing, linting, auditing). |
| [`doc/`](./doc/) | Style and workflow/PR guides. |

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Code of Conduct

We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct),
with the following additional clause:

- We respect the rights to privacy and anonymity for contributors and people in
  the community. If someone wishes to contribute under a pseudonym different to
  their primary identity, that wish is to be respected by all contributors.

## License

This repository is dual-licensed:

- **Upstream source** is licensed under
  [AGPL-3.0-only](./LICENSE), inherited from
  [signalapp/SparsePostQuantumRatchet](https://github.com/signalapp/SparsePostQuantumRatchet).
  The [Aeneas](https://github.com/AeneasVerif/aeneas)-generated Lean translation
  in `Types.lean` and `Funs.lean` in [`SrcTranslated/`](./SrcTranslated/) is a derivative of that source
  and is therefore also covered by [AGPL-3.0-only](./LICENSE).

- **Other contributions** (such as hand-written Lean code under
  [`Spqr/Math/`](./Spqr/Math/) or [`Spqr/Specs/`](./Spqr/Specs/)) are
  released under the [Apache License, Version 2.0](./LICENSE-APACHE).
