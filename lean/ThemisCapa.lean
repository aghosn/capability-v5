-- ThemisCapa — Lean 4 v2 formal specification of the Themis capability model.
--
-- v2 design: explicit `SpecState`, small-step `step` relation, flat-arena
-- finmaps. See `docs/capability-engine/aeneas-exploration.md` §10 and
-- `archive-v1/README.md` for the v1 → v2 migration rationale.
import ThemisCapa.Basic
import ThemisCapa.Domain
import ThemisCapa.Interposition
import ThemisCapa.Translation
import ThemisCapa.Switch
import ThemisCapa.Attestation
import ThemisCapa.Arena
import ThemisCapa.State
import ThemisCapa.Action
import ThemisCapa.Step
import ThemisCapa.Invariants
import ThemisCapa.Properties
import ThemisCapa.Locality
