# CPUID & MSR Policy Design

**Status**: Draft — design iteration  
**Related**: P16.6c, `docs/architecture/confidential-vm.md` §5–6

## 1. Problem

CPUID and MSR emulation for child domains is currently split across two levels:

**CPUID:**

1. **Capavisor** (`handle_cpuid_local`): handles Themis hypervisor leaves
   (0x4000_0000–0x4000_00FF) locally, applies AVX-512 / XSAVE masks to native
   CPUID results.
2. **CHV** (dom0 userspace): handles all other CPUID exits via the exit-policy
   trap mechanism.  CHV stores a per-VP CPUID table (`set_cpuid2`) and replies
   from it in `handle_cpuid_exit`.

**MSR:**

1. **Capavisor** (`handle_rdmsr_local` / `handle_wrmsr_local`): handles MSRs
   for the local exit path via a virtualisation layer (`msr_virt`) — emulates
   some, passes through safe ones, #GPs the rest.
2. **CHV** (dom0 userspace): handles all MSR exits from children via the
   exit-policy trap mechanism (same round-trip as CPUID).

This works but has drawbacks:
- Every trapped CPUID/MSR exit round-trips to dom0 userspace (VMX root → dom0
  vmresume → CHV handler → hypercall back → vmresume child).
- Dom0 can forge arbitrary CPUID/MSR responses — breaks confidentiality for
  CoCo children.
- The CoCo detection leaf (0x4000_0100) currently returns the VTOM bit and
  Themis signature to **all** domains, including dom0.  Dom0's kernel must NOT
  see a non-zero VTOM (it would activate swiotlb / CoCo mode incorrectly).

## 2. Design Goals

1. CPUID and MSR responses are part of the **domain policy** — set by the
   parent before `seal`, validated by the capability engine, enforced by the
   capavisor.
2. The capavisor handles CPUID/MSR exits **entirely in VMX root mode** (no
   round-trip to dom0) when the policy covers the leaf/MSR.
3. CHV remains the entity that **chooses** the policy (it knows the guest's
   vCPU count, features, etc.) but cannot violate it after seal.
4. The CoCo leaf (0x4000_0100) returns a per-domain VTOM value from the policy.
   Dom0 has VTOM=0.  Confidential children have VTOM=39 (bit 39).
5. MSR policy controls which MSRs a domain can read/write and what values are
   returned for emulated MSRs (e.g., synthetic Themis MSRs, TSC frequency).

## 3. Proposed Architecture

### 3.1 Unified action model

Both CPUID and MSR policies use the same three-action model (mirroring the
interrupt policy): **Trap** (forward to parent), **Native** (execute on
hardware), **Emulate** (return fixed value).

### 3.2 Generic interposition policy

A trait defines the associated types for each resource class.  The policy
and config types are generic over this trait.

```rust
/// Trait defining the types for a processor feature resource class.
pub trait ProcFeature {
    /// How to identify a single resource (e.g., CPUID leaf, MSR number).
    type Input: Ord + Copy;
    /// A range of resources [start, end] inclusive.
    type Range: Clone;
    /// The emulated value type (e.g., CpuidResult or u64).
    type Value: Clone;

    /// Check whether `input` falls within `range`.
    fn in_range(input: &Self::Input, range: &Self::Range) -> bool;
}

/// A single policy entry: what to do for a range of resources.
#[derive(Clone)]
pub enum ProcFeaturePolicy<T: ProcFeature> {
    /// Forward exits in this range to the parent domain.
    Trap(T::Range),
    /// Return a fixed value for resources in this range.
    Emulate(T::Range, T::Value),
    /// Execute natively on the physical CPU.
    Native(T::Range),
}

/// Per-domain configuration for a resource class.
#[derive(Clone)]
pub struct ProcFeatureConfig<T: ProcFeature> {
    /// Action for resources not matched by any override.
    pub default: ProcFeaturePolicy<T>,
    /// Sorted overrides, checked in order.  First match wins.
    pub overrides: Vec<ProcFeaturePolicy<T>>,
}
```

**Lookup** (O(log n) binary search on sorted overrides):

```
1. For each override, check if input is in_range()
2. First match → apply action (Trap / Native / Emulate)
3. No match → apply default
```

**Instantiation** for CPUID and MSR:

```rust
// ── CPUID ──

#[derive(Clone)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub struct Cpuid;
impl ProcFeature for Cpuid {
    type Input = u32;              // leaf number
    type Range = (u32, u32);       // (start, end) inclusive
    type Value = CpuidResult;

    fn in_range(leaf: &u32, range: &(u32, u32)) -> bool {
        *leaf >= range.0 && *leaf <= range.1
    }
}

pub type CpuidPolicy = ProcFeatureConfig<Cpuid>;

// ── MSR ──

pub struct Msr;
impl ProcFeature for Msr {
    type Input = u32;              // MSR number
    type Range = (u32, u32);       // (start, end) inclusive
    type Value = u64;

    fn in_range(msr: &u32, range: &(u32, u32)) -> bool {
        *msr >= range.0 && *msr <= range.1
    }
}

pub type MsrPolicy = ProcFeatureConfig<Msr>;
```

Added to `DomainPolicy`:

```rust
pub struct DomainPolicy {
    pub cores: u64,
    pub api: MonitorAPI,
    pub interrupts: InterruptPolicy,
    pub exits: ExitPolicy,
    pub cpuid: CpuidPolicy,       // ← NEW
    pub msrs: MsrPolicy,          // ← NEW
    pub vprocessor_states: Vec<VProcessorRef>,
    pub num_vprocessors: usize,
}
```

**Notes:**
- `Emulate(range, value)` on a range means all resources in that range return
  the same value.  Useful for MSRs (e.g., emulate a whole range with 0).
  For CPUID it's typically point entries where start == end.
- Adding a new resource class (I/O ports, etc.) means implementing
  `ProcFeature` and adding a `ProcFeatureConfig<NewType>` field to
  `DomainPolicy`.

### 3.3 MSR bitmap integration (hardware acceleration)

The VMCS MSR bitmap (4 KB) controls which MSRs cause VM exits:
- Two ranges: 0x0000_0000–0x0000_1FFF and 0xC000_0000–0xC000_1FFF
- Separate bits for read and write
- Bit set → VM exit; bit clear → no VM exit (Native)

At domain **seal** time, the capavisor can derive the MSR bitmap from the
policy:
- `Native` ranges/entries → clear the corresponding bitmap bits (no VM exit)
- `Trap` / `Emulate` / `Block` → set the bits (VM exit, then apply policy)

MSRs outside the bitmap's two ranges (0x2000–0xBFFF_FFFF) always cause VM
exits regardless of the bitmap.  The policy still applies to those.

This is a **Phase 1** optimisation for MSRs: deriving the bitmap avoids VM
exits entirely for passthrough MSRs.

### 3.4 PolicyIdentifier extension

The operations on the policy are generic — they work the same regardless of
resource kind.  A `ResourceKind` discriminant selects which policy field to
target:

```rust
#[derive(Clone, Copy)]
pub enum ResourceKind {
    Cpuid = 0,
    Msr = 1,
}

pub enum PolicyIdentifier {
    // ... existing variants (Cores, ApiMonitor, interrupts, exits) ...

    /// Set the default action for a resource class.
    /// Value: 0 = Trap, 1 = Native.
    ProcFeatureDefault(ResourceKind),

    /// Insert a Trap or Native range override.
    /// Key = range start, sub_key = range end (inclusive).
    /// Value: 0 = Trap, 1 = Native.
    ProcFeatureRange(ResourceKind),

    /// Insert an Emulate point/range override.
    /// Key = resource id (or range start for range emulate).
    /// Sub_key = word_index (multi-word values need multiple calls).
    /// Value: packed emulated value (encoding is resource-specific).
    ProcFeatureEmulate(ResourceKind, u8),  // (resource_kind, word_index)
}
```

**`set_policy` dispatch** in the engine — the generic `ProcFeatureConfig<T>`
provides `set_default()`, `insert_override()` methods.  Only emulate value
unpacking is resource-specific:

```rust
match id {
    ProcFeatureDefault(rk) => {
        // Constructs Trap(full_range) or Native(full_range) as default
        match rk {
            Cpuid => child.policy.cpuid.set_default(value)?,
            Msr   => child.policy.msrs.set_default(value)?,
        }
    }
    ProcFeatureRange(rk) => {
        // Inserts Trap((start,end)) or Native((start,end))
        match rk {
            Cpuid => child.policy.cpuid.insert_range(key, sub_key, value)?,
            Msr   => child.policy.msrs.insert_range(key, sub_key, value)?,
        }
    }
    ProcFeatureEmulate(Cpuid, word) => {
        // word 0: (eax << 32) | ebx,  word 1: (ecx << 32) | edx
        child.policy.cpuid.set_emulate_word(key, word, value)?;
    }
    ProcFeatureEmulate(Msr, word) => {
        // word 0: value[31:0],  word 1: value[63:32]
        child.policy.msrs.set_emulate_word(key, word, value)?;
    }
}
```

`set_default`, `insert_range`, and `lookup` are implemented once on
`ProcFeatureConfig<T>` (they only need `T::Range` and `in_range()`).
`set_emulate_word` is resource-specific because it unpacks `u64` into
`T::Value`.

### 3.5 Hypercall ABI

All use the existing `THEMIS_SET_POLICY` hypercall (opcode 0x1E).  Three new
`policy_kind` constants, with `resource_kind` packed into `key` or a
dedicated argument:

| kind | value | key | sub_key | value arg |
|------|-------|-----|---------|-----------|
| `INTERPOSITION_DEFAULT` | 10 | resource_kind | — | 0=Trap, 1=Native |
| `INTERPOSITION_RANGE` | 11 | start | end | 0=Trap, 1=Native |
| `INTERPOSITION_EMULATE` | 12 | resource_id | word (0 or 1) | packed value |

For `INTERPOSITION_RANGE` and `INTERPOSITION_EMULATE`, the resource_kind
must also be conveyed.  Two options:

- **(a)** Encode in `kind`: `kind = 10 + op + resource_kind * 3`.
  CPUID = kinds 10/11/12, MSR = kinds 13/14/15.
- **(b)** Add `resource_kind` as an extra argument (requires packing into an
  existing arg since the hypercall has 5 args).

→ **Decision**: Option (a) for simplicity — 3 constants per resource kind,
new resources add 3 more.  The `PolicyIdentifier` enum abstracts this away.

```
// CPUID (resource_kind = 0)
INTERPOSITION_DEFAULT_CPUID  = 10
INTERPOSITION_RANGE_CPUID    = 11
INTERPOSITION_EMULATE_CPUID  = 12

// MSR (resource_kind = 1)
INTERPOSITION_DEFAULT_MSR    = 13
INTERPOSITION_RANGE_MSR      = 14
INTERPOSITION_EMULATE_MSR    = 15
```

### 3.6 Capavisor enforcement

Both handlers use `ProcFeatureConfig<T>::lookup(input)` which returns the
matching `ProcFeaturePolicy<T>` variant:

**CPUID exit handler**:

```
1. leaf = guest RAX
2. match domain.cpuid.lookup(leaf):
   Emulate(_, result) → inject (eax, ebx, ecx, edx), advance RIP
   Native(_)          → execute native CPUID + standard masks, advance RIP
   Trap(_)            → return PolicyDriven (forward to parent)
```

**MSR exit handler**:

```
1. msr = guest RCX
2. match domain.msrs.lookup(msr):
   Emulate(_, value) → RDMSR: inject value; WRMSR: drop, advance RIP
   Native(_)         → execute native RDMSR/WRMSR, advance RIP
   Trap(_)           → return PolicyDriven (forward to parent)
```

### 3.7 Validation rules

In `Capability::set_policy`:
- **Pre-seal only**: like all policy mutations.
- **No monotonicity constraint** (unlike cores): the parent can set any values.
- **No overlap**: inserting a range that overlaps an existing range replaces
  the overlapping portion (or reject — TBD).
- **Size limits**: cap ranges at ~64 entries and emulates at ~64 entries each.
  Sufficient for practical use; prevents memory exhaustion.

### 3.8 Example: CoCo child domain setup

CHV configures a confidential child domain's CPUID policy:

```
// Default: trap to CHV (CHV handles most CPUID leaves today)
set_policy(child, DEFAULT_CPUID, 0, 0, TRAP)

// Themis hypervisor leaves: native (capavisor handles locally)
set_policy(child, CPUID_RANGE, 0x40000000, 0x400000FF, NATIVE)

// CoCo detection leaf: emulate with VTOM=39 + signature
set_policy(child, CPUID_EMULATE, 0x40000100, 0, (39 << 32) | u32("Them"))
set_policy(child, CPUID_EMULATE, 0x40000100, 1, (u32("isCo") << 32) | u32("Co\0\0"))

// Leaf 0x15 (TSC/core crystal clock): native
set_policy(child, CPUID_RANGE, 0x15, 0x15, NATIVE)
```

Dom0's CPUID policy: no CoCo emulate entry → VTOM=0 → no CoCo activation.

## 4. Migration Path

### Phase 1 (CoCo enablement)
- Add `CpuidPolicy` and `MsrPolicy` structs to `DomainPolicy`
- Add new `PolicyIdentifier` variants and `policy_kind` constants
- Wire `set_policy` handling in the engine (insert ranges, emulates)
- Update capavisor CPUID/MSR exit handlers to consult policy
- Derive VMCS MSR bitmap from `MsrPolicy` at seal time
- Remove hardcoded `CPUID_THEMIS_COCO` response; it becomes an emulate entry
- CHV sets CoCo CPUID entries for confidential children

### Phase 2 (future — full virtualization)
- Move all CHV CPUID/MSR handling into capavisor policy
- Deprecate `set_cpuid2` in CHV
- Add subleaf granularity for CPUID emulate entries
- WRMSR shadow storage for emulated MSRs that need read-back

## 5. Open Questions

1. **Range overlap handling**: reject overlapping inserts, or silently replace?
   Reject is simpler and prevents accidental misconfiguration.

2. **Subleaf granularity**: not needed for Phase 1.  The `CpuidEmulateEntry`
   could grow a `subleaf` field later (topology leaf 0x0B needs it).

3. **WRMSR to emulated MSRs**: currently dropped.  Should we shadow-store for
   read-back?  Not needed for CoCo; defer.

4. **Should Themis signature leaves (0x4000_0000) also be policy-controlled?**
   No — those identify the hypervisor itself and are the same for all domains.
   They remain hardcoded in the capavisor.  Only domain-specific leaves
   (like 0x4000_0100) go through policy.
