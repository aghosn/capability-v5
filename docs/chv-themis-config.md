# CHV-side Themis policy configuration — design doc

> **Status: DRAFT — iteration in progress.**  This file inventories the
> Themis-specific behaviour CHV currently exposes, and proposes a
> declarative config surface (JSON/YAML/TOML) so users and tests can
> customise a child domain's policy without recompiling CHV.

## Motivation

Everything CHV does that touches Themis today is either **hardcoded in
Rust** or gated by the single **`--platform confidential=on`** toggle.
That has three visible costs:

1. **Test coverage gap.**  Eunomia workloads that want to exercise all
   three policy configurations (Native / Trap / Emulate) and both
   default actions cannot do so without patching `vm_state.rs`.  The
   MSR and CPUID test workloads currently live inside a single fixed
   policy shape (`default=Native`, `Emulate(0x6E0)`, `Emulate(0x1B)`
   when x2APIC virt is supported) — Trap-to-parent is untested from
   any workload.
2. **User customisation blocked.**  A downstream user who wants a
   different Themis child profile (say, `default=Trap` + explicit
   Native whitelist for auditing) has to fork CHV.
3. **Not reproducible.**  Reviewing a configuration means reading the
   Rust code in `hypervisor/src/themis/vm_state.rs`.  Nothing captures
   "this VM was launched with policy X" in an artefact you can commit,
   diff, or attach to a bug report.

## Inventory: what CHV currently controls

All paths below are relative to `cloud-hypervisor/`.

### 1. Confidential / CoCo mode

**Trigger:** `--platform confidential=on` (`vmm/src/config.rs:816`).

**Read:** `HypervisorVmConfig::confidential` → `ThemisHypervisor::create_vm`
(`hypervisor/src/themis/hypervisor_impl.rs:72`).

**Effects:**
- Derives `vtom_bit = cpuid(0x80000008).eax[7:0] - 1`
  (`hypervisor_impl.rs:119-123`).
- Switches guest RAM allocation from ALIAS to CARVE
  (`vm_impl.rs:362-365`).
- Splits guest memory around known shared regions (EBDA/ACPI) with a
  vTOM mirror ALIAS (`vm_state.rs:76-158`).
- MMIO emulator becomes VTOM-aware (`vcpu.rs:912-950`,
  `emulator.rs:35-110`).
- Pushes an Emulate CPUID leaf `0x40000100`
  (signature `ThemisCoCo`, EAX = vTOM bit) at seal
  (`vm_state.rs:468-479`).

### 2. MSR interposition policy

**Trigger:** none — always pushed at seal by
`ensure_msr_policy_pushed` (`vm_state.rs:206-303`).

**Currently hardcoded:**
- `MSR_DEFAULT = Native` (line 226).
- `MSR_EMULATE(0x6E0, value=0)` — IA32_TSC_DEADLINE, captured by
  capavisor's registered emulator (line 237).
- When `themis_x2apic_virt_supported()` returns true:
  - `MSR_RANGE(0x800..=0x82F, Native)` — x2APIC LAPIC page
  - `MSR_RANGE(0x830..=0x830, Trap)` — ICR, software-routed IPI
  - `MSR_RANGE(0x831..=0x83F, Native)` — rest of x2APIC page
  - `MSR_EMULATE(0x1B, value = 0xFEE00000|EN|EXTD)` — IA32_APIC_BASE
    pinned, WRMSR consumed by capavisor's registered emulator

### 3. CPUID interposition policy

**Trigger:** none — always pushed at seal by the CPUID block in
`vm_state.rs:343-465`.

**Currently hardcoded:**
- Every CPUID entry from `self.cpuid_entries` (the KVM-style leaf
  table that CHV builds through its normal supported-CPUID plumbing)
  becomes `CPUID_EMULATE(leaf, subleaf)` — 2 policy calls per entry
  (word 0 = eax:ebx, word 1 = ecx:edx).
- Leaf 1 ECX bit 21 (X2APIC) is unconditionally forced when
  `x2apic_virt` is true (line 366-370).
- `CPUID_RANGE(0x40000000..=0x4FFFFFFF, Native)` split around any
  Emulate leaves so capavisor handles the hypervisor leaves natively
  (`vm_state.rs:425-465`).
- Per-ivshmem-device Emulate leaves `0x40000004` subleaves
  (`vm_state.rs:390-411`).
- CoCo detection leaf `0x40000100` — only when `confidential=on`
  (`vm_state.rs:468-479`).

### 4. Address-space / memory geometry (not policy per se)

- Number of shared meta pages: `ThemisHypervisor.shared_meta_pages`
  (fixed at construction, `hypervisor_impl.rs`).
- Per-VP meta page count: `ThemisHypervisor.vp_meta_pages`
  (also fixed at construction).
- Ivshmem BAR layout: from `--ivshmem` CLI plumbing, but the
  Themis-facing capa engine policy is derived (`vm_state.rs:390-411`).

### 5. Attestation / signing

Not driven by any config surface — nonces are supplied by the userspace
test tool `test_attestation`.  Nothing in `vm_state.rs` today.

### 6. Comm-ring / doorbell / IPI routing

Fixed by capavisor at boot.  CHV has no input.

## What we already inherit from CHV natively

CHV's own config surface (`vmm/src/config.rs`, `vmm/src/vm_config.rs`)
is a mixed CLI-option + JSON schema (`api.json`).  Options are string-
based (`key=value,key=value`) parsed by `OptionParser` and mirrored to
serde structs.  The API server accepts the same struct as JSON.

The natural extension points inside CHV are:

- **Add fields to `PlatformConfig`** — that's where `confidential`,
  `tdx`, `sev_snp` already live.  Parser already tolerates unknown
  keys behind features.  Downside: `PlatformConfig` becomes a grab-bag.
- **New top-level `ThemisConfig`** — cleaner separation, easy to gate
  behind `#[cfg(feature = "themis")]`, becomes its own field on
  `VmConfig` and its own `--themis-config` CLI option.
- **Nested inside `--platform`** — e.g.
  `--platform confidential=on,themis_config=/path/to/themis.json`.
  Simplest for users, keeps the flag surface flat.

## Proposal (v0.1 — decisions locked 2026-07-16)

Add a **top-level `themis: Option<ThemisConfig>` serde field on
`VmConfig`**.  Loaded from disk via a new
**`--themis-config <path.json>`** CLI flag, or supplied inline as
part of the JSON `VmConfig` passed to the REST API.  Format is
**JSON** to match CHV's existing `api.json` style.

**Backward compat:** `--platform confidential=on` remains as
shorthand.  Precedence: if `--themis-config` is supplied, it wins and
`confidential=on` (if also present) triggers a warning.

**Attestation relationship:** the config file is a **user-side
reference artefact** — the verifier reads it to know what policy
shape the attestation report should reflect.  CHV does **not** hash
or embed the config file into the report; capavisor measures the
actual applied policy state.  Users are expected to check the
`themis.json` they launched with into source control alongside
whatever else they use to reason about the attestation.

**Parser error strategy:** reject unknown fields, overlapping
ranges, unknown action strings, and misplaced `auto:` sentinels
with clear messages naming the offending line/field.  No dedicated
`themis-lint` tool for v0 — CHV's own load-time validation is the
lint.

### Schema sketch (JSON)

The `policies` section is a **1-to-1 mirror of `DomainPolicy`** in
`capa-engine/src/domain.rs:482` (`cores`, `api`, `interrupts`,
`exits`, `msrs`, `cpuid`).  Everything outside `policies` is
Themis-specific CHV state that isn't already expressible via stock
CHV config.

**Explicitly NOT in this file** (already covered by stock CHV
config, do not duplicate):
- vCPU count → `--cpus boot=N` (`CpusConfig.boot_vcpus`,
  `vm_config.rs:69`).
- RAM size / NUMA / hugepages → `--memory` (`MemoryConfig`).
- Ivshmem devices → `--ivshmem path=…,size=…,mode=…,count=…`
  (`IvshmemConfig`, `vm_config.rs:697`, already extended by Themis
  with `mode` and `count`).
- Disks, net, serial, etc. → their existing CHV flags.

```jsonc
{
  // 1. Identity + top-level mode selectors.
  "general": {
    "name": "child-0",             // free-form label, propagated to logs
    "confidential": false,         // ⇐ replaces --platform confidential=on
    "vtom_bit": null,              // null = auto-derive from CPUID leaf 0x80000008,
                                   // integer = explicit override
    "shared_regions": [            // confidential-mode ALIAS carve-outs
                                   // (memory that stays plaintext-shared in CoCo).
                                   // NOT ivshmem — see note above.
                                   // Today hardcoded in vm_state.rs:76-158 (EBDA/ACPI).
      { "name": "EBDA", "gpa": "0x9FC00", "size": "0x400" },
      { "name": "ACPI", "gpa": "auto",    "size": "auto"  }
    ]
  },

  // 2. Capability-engine policy — mirrors DomainPolicy 1-to-1.
  "policies": {

    // DomainPolicy.cores : u64 (bitmap of allowed physical cores)
    "cores": {
      "allowed": [0, 1, 2, 3]      // list form; CHV builds the bitmap.
                                   // Alt: "mask": "0x0F".
                                   // Must be a subset of the parent's cores.
    },

    // DomainPolicy.api : MonitorAPI (bitmap of allowed monitor calls)
    "api": {
      "allow": "ALL"               // or explicit list: ["carve","alias","seal",
                                   //   "send_channel","accept_channel","register_comm",
                                   //   "revoke","get_chan","map_self","accept_at",
                                   //   "send_memory_sealed","send_memory_unsealed",
                                   //   "receive_after_seal"]
                                   // Must be a subset of the parent's API.
    },

    // DomainPolicy.interrupts : InterruptPolicy (default + per-vector overrides).
    // VectorPolicy = { visibility, read_set, write_set }.
    "interrupts": {
      "default": {
        "visibility": "NotReport", // "Deliver" | "Report" | "NotReport"
        "read_set":  "ALL",
        "write_set": "ALL"
      },
      "overrides": [
        { "vector": 0xEC, "visibility": "Deliver", "read_set": "NONE", "write_set": "NONE" }
      ]
    },

    // DomainPolicy.exits : ExitPolicy (default + per-VMEXIT-reason overrides).
    // ExitAction = { trap: bool, read_set, write_set }.
    "exits": {
      "default": { "trap": true,  "read_set": "ALL", "write_set": "ALL" },
      "overrides": [
        { "reason": "EPT_VIOLATION", "trap": false, "read_set": "NONE", "write_set": "NONE" }
      ]
    },

    // DomainPolicy.msrs : MsrPolicy (default + per-MSR overrides).
    "msrs": {
      "default": "Native",         // "Native" | "Trap"
      "overrides": [
        { "range": [0x800, 0x82F], "action": "Native" },
        { "range": [0x830, 0x830], "action": "Trap"   },
        { "msr":   0x6E0,          "action": "Emulate", "value": 0 },
        { "msr":   0x1B,           "action": "Emulate", "value": "0xFEE00000 | EN | EXTD" }
      ]
    },

    // DomainPolicy.cpuid : CpuidPolicy (default + per-(leaf,subleaf) overrides).
    "cpuid": {
      "default": "Native",
      "hypervisor_range_native": true,     // shortcut for 0x40000000..=0x4FFFFFFF Native
      "overrides": [
        {
          "leaf": "0x40000100", "subleaf": 0,
          "action": "Emulate",
          "eax": "auto:vtom_bit",   // sentinel; CHV fills in at seal (from general.vtom_bit)
          "ebx": "Them", "ecx": "isCo", "edx": "Co  "
        },
        {
          "range": [ [0x0F, 0], [0x0F, "0xFFFFFFFF"] ],
          "action": "Trap"
        }
      ]
    }
  },

  // 3. Cross-domain shared memory (ivshmem devices under Themis control).
  //     Reconciled with --ivshmem CLI at parse time; see rules below.
  "comm": {
    "ivshmem": [
      {
        "id": 0,                             // stable id; matches CLI --ivshmem order if unspecified
        "path": "/tmp/themis-shm-0",
        "size": "2MiB",
        "capa_mode": "carve",                // "alias" | "carve" | "plug" | "none"
        "count": 2,                          // additional domains that may plug in (creator only)
        "cpuid_leaf": "0x40000004"           // discovery leaf (defaults to 0x40000004)
      }
    ]
  }
}
```

### Notes on this hierarchy

- **`policies` is a 1-to-1 mirror of `DomainPolicy`.**  Six children,
  same names, same shapes:
  - `cores`  ← `DomainPolicy.cores : u64` (bitmap)
  - `api`    ← `DomainPolicy.api : MonitorAPI`
  - `interrupts` ← `InterruptPolicy` (`domain.rs:240`)
  - `exits`  ← `ExitPolicy` (`domain.rs:299`)
  - `msrs`   ← `MsrPolicy` (`capa-engine/src/interposition.rs`)
  - `cpuid`  ← `CpuidPolicy` (`capa-engine/src/interposition.rs`)
- **All override lists share the same `{ default, overrides: [...] }`
  shape**, because that's what `InterruptPolicy` / `ExitPolicy` /
  `MsrPolicy` / `CpuidPolicy` actually are.  Parser is uniform.
- **Symbolic names accepted everywhere.**  Interrupt vectors as
  integers, VMEXIT reasons by name (`"EPT_VIOLATION"`, etc.), register
  sets as `"ALL"` / `"NONE"` / bit-list.  Numeric fallback always
  available.  Unknown symbols → hard error naming the field.
- **`general` is intentionally minimal**: only `confidential`,
  `vtom_bit`, and the CoCo-mode `shared_regions` list — because
  vCPU count, RAM, ivshmem devices, disks, and so on are already
  covered by CHV's native config surface and MUST NOT be duplicated
  here.
- **`shared_regions` is not ivshmem.**  It's the list of plaintext
  carve-outs needed by a confidential guest (EBDA, ACPI) — today
  hardcoded in `vm_state.rs:76-158`.  If we ever want users to add
  their own plaintext regions to a CoCo guest, this is where they
  go.  Empty (or auto-defaulted to the current EBDA/ACPI pair) in the
  non-confidential path.
- **`comm.ivshmem` deliberately mirrors `IvshmemConfig`** (from
  `cloud-hypervisor/vmm/src/vm_config.rs:697`).  The Themis-specific
  fields we added to that struct (`mode`, `count`) appear as
  `capa_mode` and `count` here.  Users may define ivshmem devices
  in *either* the themis config *or* on the `--ivshmem` CLI — both
  produce entries in the same in-memory `VmConfig.ivshmem` list.

### Ivshmem reconciliation rules (`--ivshmem` vs `themis.comm.ivshmem`)

Users may add ivshmem devices from either surface.  At parse time
CHV builds a single `Vec<IvshmemConfig>` by merging both sources
with these rules:

1. **Key = `id`** (integer).  If unspecified in the JSON entry,
   `id = index` in the themis config `ivshmem` array.  `--ivshmem`
   entries get ids assigned in CLI order **starting after** the
   highest themis-config id (so pure-CLI users see 0, 1, 2… as
   today).
2. **Same `id` in both sources → error.**  Users must pick one
   source of truth per device.  Message: `"ivshmem id N defined
   in both --themis-config and --ivshmem"`.
3. **Same `path` in both sources → error** (belt-and-braces; catches
   duplicated file-backed regions even without id collision).
4. **`capa_mode: "none"` in themis config** is equivalent to a
   vanilla `--ivshmem` (no capa-engine backing) — useful when a user
   wants a single config file to fully describe the VM without
   splitting across CLI flags.
5. **CLI-only fields default** on themis-config entries: `iommu`,
   `pci_segment`, and any other `IvshmemConfig` field not listed in
   the themis schema fall back to `IvshmemConfig::default()`.
   Symmetric on the CLI side.
6. **Attestation implication**: the reconciled `Vec<IvshmemConfig>`
   is what capavisor measures; users who want reproducibility should
   put all ivshmem devices in the themis config (single artefact).

## Default profiles (no `--themis-config` provided)

Today the "defaults" live as Rust code in `vm_state.rs:206-479` and
`hypervisor_impl.rs:119-124`.  That has two problems:

1. **Not visible.**  Users can't read what policy their VM will get
   without opening a `.rs` file.
2. **Not overridable in the small case.**  Even trivial tweaks force
   a full recompile.

**Proposal**: ship the defaults as **standalone JSON files
in the repo**, embedded into the CHV binary at build time so
distribution stays as a single binary:

| Profile | File on disk | Loaded when |
|---|---|---|
| **standard** | `cloud-hypervisor/hypervisor/src/themis/defaults/standard.json` | `--themis-config` absent AND `--platform confidential=off` (or unset) |
| **confidential** | `cloud-hypervisor/hypervisor/src/themis/defaults/confidential.json` | `--themis-config` absent AND `--platform confidential=on` |

The Rust side just does:

```rust
const STANDARD_DEFAULT:     &str = include_str!("defaults/standard.json");
const CONFIDENTIAL_DEFAULT: &str = include_str!("defaults/confidential.json");
```

so the JSON is authored, reviewed, diffed, and syntax-highlighted as
a plain file — `include_str!` only controls *when* it's read (build
time), not *where* it's authored.

**Why embed at build time rather than load from disk at launch:**

- **Single-binary distribution.**  CHV ships as one executable
  today; runtime-loaded defaults would need an install path, an
  env var, or a `$prefix/share/cloud-hypervisor/` convention that
  breaks in containers.
- **Attestation lock.**  Verifier reads the JSON from the exact
  CHV source SHA the binary was built from; a runtime file could
  be swapped post-build without changing the CHV hash.
- **Tests are hermetic.**  No cwd-relative lookups.

A dev flag **`--themis-default-override <path>`** loads the
appropriate default file from disk at launch instead of using the
embedded copy — useful for iterating on the JSON without a rebuild.
Off by default; logs a loud warning when used.

### Composition when a user config IS provided

The user's file is a **complete replacement** — no deep merge, no
partial overlay.  Rationale (from the attestation-reference decision
in v0.1): the verifier reads a single file and can reason about the
policy in one place.  Deep merging hides what's actually in effect.

To keep small tweaks ergonomic, the top-level schema gains an
optional field:

```jsonc
{
  "extends": "confidential",   // or "standard", or a file path
  // …only the fields you want to override…
}
```

Semantics: load the named/pathed base, then **shallow-merge** the
user's top-level sections (`general`, `policies`, `comm`).  Within
each section, fields present in the user's file **replace** the base
wholesale (no per-`overrides[]` diff).  So:

- `general.confidential = true` in the extending file → `true`
- `general.shared_regions = [...]` in the extending file →
  fully replaces the base's list (no append)
- `policies.msrs = { default: "Trap", overrides: [...] }` → fully
  replaces the base's `msrs`
- Any section not mentioned → inherited verbatim from base

Rejects overly-clever cases:
- `extends` chaining more than one level → error (keeps merge
  auditable)
- `extends` referencing an unknown built-in name AND an unreadable
  path → error with both interpretations enumerated

### Loading order at CHV startup

```
1. Parse CLI (--themis-config path, --platform confidential=on/off, ...)
2. If --themis-config absent:
     load defaults[confidential ? confidential.json : standard.json]
   Else:
     load user file
     if it has "extends":
       load base (built-in name OR path)
       shallow-merge user's sections onto base
3. Reconcile ivshmem list with --ivshmem CLI entries (see rules above)
4. Validate (unknown symbols, overlapping ranges, subset checks)
5. Apply at seal time via existing THHV_SET_POLICY plumbing
```

### Attestation of defaults

The bundled `standard.json` / `confidential.json` are checked into
the CHV source tree.  Verifiers can read them from the same commit
CHV was built from.  When a user launches with a bare
`--platform confidential=on` (no `--themis-config`), the reference
artefact for attestation is *the bundled `confidential.json` at
CHV's build commit*.  The verifier is expected to have that file
alongside CHV's commit hash.  No opaque hardcoded defaults.



For the MSR test workload we want to spawn (via separate CHV
invocations, or later via API) several children with different
policies:

| Case | Policy shape | Guest expectation |
|---|---|---|
| `msr-native-default` | `default: Native`, no overrides | RDMSR/WRMSR run natively; sampled TSC differs across two reads |
| `msr-trap-default`   | `default: Trap`, minimal Native whitelist | Any WRMSR outside whitelist forwarded to CHV (observable via a scratch MSR the harness watches) |
| `msr-emulate-handler`| `MSR_EMULATE(0x1B, ...)` | Read returns pinned value; write consumed |
| `msr-emulate-nohdlr` | `MSR_EMULATE(some MSR not in capavisor registry)` | Read returns stored value; write forwarded to CHV |

Analogous four for CPUID.  Today all four for each category are
impossible without patching Rust.

### Open questions — RESOLVED (2026-07-16)

1. **Where does the config live?** → **New top-level `--themis-config
   <path.json>` CLI flag, populating a top-level
   `VmConfig.themis: Option<ThemisConfig>` serde field.**
   Rationale: schema needs nesting (ranges, per-item overrides) that
   flat `--platform key=value` can't express; users treat the config
   as an attestation reference artefact (see question 3), so a
   discrete file matches the mental model. `--platform
   confidential=on` remains as backward-compat sugar — if both are
   provided, `--themis-config` wins and CHV logs a warning.
2. *(deferred — attestation params derived from policy hash)*
3. **Is the config measured?** → **No.** The config file is a
   **user-side reference** used by the verifier to check the
   attestation report against the policy it expected. CHV itself
   does not hash or include the file in the report; capavisor
   measures the actual pushed policy state.
4. **Format?** → **JSON.** Consistent with CHV's existing
   `api.json`, no new parser dependency, serde-native.
5. **Themis-lint tool?** → **Not needed initially.** Instead, invest
   in **clear parser error messages** on the CHV side: reject
   unknown fields, overlapping ranges, unknown action strings, and
   `auto:` sentinels for constants that don't accept them.  A dry-run
   flag (`--themis-config-check`) may come later if users ask.


## Iteration log

- **v0** (initial draft): inventory + JSON schema sketch, motivated
  by needing to write eunomia MSR / CPUID coverage tests.
- **v0.1** (2026-07-16): decisions locked — new `--themis-config`
  CLI + top-level `VmConfig.themis`, JSON format, config is a
  user-side attestation reference (not measured by CHV), no dedicated
  lint tool. See RESOLVED open-questions section.
- **v0.2** (2026-07-16): reorganised schema into four sections
  (`general`, `memory`, `policies`, `comm`) where `policies` is a
  1-to-1 mirror of `DomainPolicy` in
  `capa-engine/src/domain.rs:482` — six children `cores`, `api`,
  `interrupts`, `exits`, `msrs`, `cpuid`.  Added allowed-cores,
  monitor-API allowlist and interrupt policy per user request.
- **v0.3** (2026-07-16): dropped duplication with stock CHV config.
  Removed `general.num_vprocessors` (already `CpusConfig.boot_vcpus`),
  removed the `memory` section (meta pages are per-hypervisor
  constants, not per-VM), removed the `comm` section (ivshmem is
  already fully covered by `--ivshmem` including the Themis-added
  `mode`/`count` fields on `IvshmemConfig`; doorbell vector is
  capavisor-side).  `shared_regions` (CoCo plaintext carve-outs)
  moved into `general` and clarified as distinct from ivshmem.
- **v0.4** (2026-07-16): reversed the ivshmem drop — user wants
  ivshmem entries expressible in the themis config since Themis
  augments the CHV ivshmem model.  Added back `comm.ivshmem[]`
  mirroring `IvshmemConfig` (with `capa_mode`/`count`) and a
  reconciliation rules block for the `--ivshmem` vs themis-config
  merge (id-keyed, error on collision).  Added a new **Default
  profiles** section: two bundled JSON files
  (`defaults/standard.json`, `defaults/confidential.json`) embedded
  via `include_str!`, replacing the hardcoded defaults in
  `vm_state.rs`.  User configs may use `extends: "standard" |
  "confidential" | <path>` for shallow-merge overlays; otherwise
  user file is a complete replacement.

