# Address Translation Layer — Design Document

> **Status**: Draft
> **Tracking**: `todo.md` #F1

## 1. Problem Statement

Today the capability engine operates under an **identity-map assumption**: every
`ChangeRights` update sets `physical == address` (i.e. the guest sees memory at
the same address as the host physical address).  This works for bare-metal
monitors that identity-map all of physical memory, but breaks on platforms with
a **two-dimensional page table** (Intel EPT / AMD NPT) where the monitor
controls a per-domain GPA→HPA mapping.

A second, forward-looking requirement is **cache-color awareness**.  On
cache-colored platforms a physical range may contain pages of different colors,
and only a subset of those colors may be assigned to a given domain.  The
translation layer must **compact** the authorized pages into a contiguous guest
address range so the domain sees a gap-free virtual region.

Both features share the same underlying need: a per-domain function that
translates physical addresses (HPA) into guest addresses (GPA), with the
engine maintaining the bookkeeping and emitting the correct GPA in every
`ChangeRights` update.

---

## 2. Terminology

| Term | Meaning |
|------|---------|
| **HPA** | Host Physical Address — the address on the physical bus |
| **GPA** | Guest Physical Address — the address visible to the domain |
| **Color** | Cache-partition identifier for a physical page (platform-defined) |
| **Color bitmap** | Per-capability bitmask selecting which colors are authorized |
| **Compaction** | Packing authorized pages into a contiguous GPA range |

---

## 3. Goals and Requirements

### 3.1 Core Requirements

1. **Feature-gated** — the entire translation layer is behind a Cargo feature
   (e.g. `feature = "address_translation"`).  When absent, the engine behaves
   exactly as today: identity-mapped, zero overhead.

2. **Isolated module** — translation logic lives in its own module
   (`src/translation.rs` or `src/translation/`).  The core capability engine
   (`capability.rs`, `view.rs`) calls into it through a narrow interface.
   No `#[cfg]` conditionals scattered through the codebase.

3. **No double-mapping of an HPA** — a given physical page may appear at most
   once in any single domain's GPA space.  Enforced at `send` / `accept` time.

4. **No aliasing of a GPA** — a guest address may map to at most one physical
   address within a domain.  Enforced at mapping-registration time.

5. **Carved-gap exclusion** — after a carved sub-region is sent away, no new
   GPA mapping may be created over those HPAs in the parent until the child is
   revoked and the parent regains the region.  This prevents collisions at
   revocation time.

6. **Correct `UpdateBatch`** — `ChangeRights` updates carry the correct GPA
   in the `address` field and the HPA in the `physical` field.

7. **Attestation** — the GPA mapping for each memory region appears in the
   attestation report.

### 3.2 Cache-Color Requirements

8. **Platform-provided color function** — the `Platform` trait gains a method
   to determine the color of a physical page (or a method that returns the
   page size and the number of colors).

9. **Color bitmap on capabilities** — `MemoryRegion` or `Access` gains an
   optional color bitmap that restricts which physical pages within the range
   are actually mapped.

10. **Contiguous compaction** — when a colored capability is mapped into a
    domain, the translation layer places the authorized pages at consecutive
    GPAs.  The domain sees a contiguous region whose size equals
    `page_size × popcount(color_bitmap ∩ pages_in_range)` rather than the
    full HPA range.

11. **Monotonicity** — a child's color bitmap must be a subset of the parent's.

---

## 4. Current Architecture (Status Quo)

### 4.1 How addresses flow today

```
MemoryRegion.access.start  ─────────────────────────────┐
                                                        │ (identity)
Update::ChangeRights { address, physical, ... }         │
                        │         │                     │
                        └─────────┘                     │
                        both set to access.start  ──────┘
```

All update-emission sites use `access.start` for both `address` (GPA) and
`physical` (HPA).  There are **four** emission sites:

| Site | File | What it emits |
|------|------|---------------|
| `revoke_subtree` — unmap child | `capability.rs:395` | `ChangeRights(NONE)` for child owner |
| `revoke_subtree` — remap parent | `capability.rs:402` | `ChangeRights(parent_rights)` for parent owner |
| `revoke_subtree` — unmap alias | `capability.rs:424` | `ChangeRights(NONE)` for alias owner |
| `view_diff` (used by send, carve) | `view.rs:234` | Sweep-line diff of `AddressSpaceView` |

### 4.2 Where translation must hook in

The translation layer needs to intercept at two levels:

1. **Bookkeeping** — when a capability is sent/accepted/revoked, update the
   per-domain GPA map.
2. **Update emission** — when `ChangeRights` is constructed, look up the GPA
   for the given HPA range instead of using the identity.

---

## 5. Proposed Design

### 5.1 Module Structure

```
src/
├── translation.rs        (or translation/mod.rs if it grows)
│   ├── AddressMap         — per-domain HPA↔GPA bookkeeping
│   ├── ColorPolicy        — color bitmap logic
│   └── translate()        — HPA → GPA lookup for update emission
└── ...existing files...
```

### 5.2 Should the `AddressMap` Track Access Rights?

The `AddressMap` must track GPA↔HPA translations.  A key design question
is whether it should **also** track access rights (`Rights`) per entry, or
leave rights entirely to the capability tree and `AddressSpaceView`.

#### The problem: carve with reduced rights

Consider a parent with `[0x0..0x40000) RWX` as a single mapping entry.
A child is carved at `[0x10000..0x20000) RW` (rights attenuated).

The parent still has access to the carved range, but the rights on that
sub-range differ from the surrounding region.  What happens in the
`AddressMap`?

#### Decision: Translation + rights (Option B) ✅

Each `MappingEntry` carries `Rights`.  When rights change (e.g. at carve
time), the entry is split:

```
After carve [0x10000..0x20000) RW:
  AddressMap:  [0x0..0x10000) Mapped RWX         ← split at carve time
               [0x10000..0x20000) Mapped RW
               [0x20000..0x40000) Mapped RWX

After send carved region:
  AddressMap:  [0x0..0x10000) Mapped RWX         ← middle → Blocked
               [0x10000..0x20000) Blocked
               [0x20000..0x40000) Mapped RWX
```

**Why Option B**:

- The `AddressMap` is a **self-contained picture** of the domain's GPA
  space — each entry has address, size, rights, and HPA.  No need to
  cross-reference the capability tree for translation or attestation.
- Send-time splitting is **trivial** because the carved region is already
  its own entry (the split happened at carve time).
- Enables a **leaner locking profile**: the `AddressMap` can produce
  correct `ChangeRights` updates (with GPA, rights, and HPA) without
  re-locking the capability tree.  This is particularly valuable when
  processing updates across operations — the translation layer can work
  from its own consistent snapshot.
- `fixup_updates` can **validate** rights consistency against the
  `AddressMap` as a cross-check.
- **Attestation** can read the complete translated view directly from the
  `AddressMap`.

<details>
<summary>Rejected alternative: Option A — Translation only (no rights)</summary>

The `AddressMap` stores only GPA↔HPA mappings.  Rights live exclusively in
the capability tree.  `view_diff` computes rights changes and emits
`ChangeRights` updates in HPA space; the `fixup_updates` post-pass
translates addresses.

```
After carve [0x10000..0x20000) RW:
  AddressMap:  [0x0..0x40000) Mapped            ← unchanged, one entry
  ChangeRights updates (from view_diff):
    (parent, 0x10000, 0x10000, RW)              ← fixup rewrites to GPA

After send carved region:
  AddressMap:  [0x0..0x10000) Mapped             ← split happens here
               [0x10000..0x20000) Blocked
               [0x20000..0x40000) Mapped
```

Pro: fewer entries, no duplication with capability tree.
Con: `fixup_updates` must handle sub-range translations (GPA computed by
offset within a larger entry).  AddressMap is incomplete without the
capability tree.  Locking profile is heavier — must hold capability tree
locks during translation.

**Rejected** because it pushes complexity into `fixup_updates`, requires
the capability tree for a complete picture, and prevents the leaner
locking profile that Option B enables.
</details>

---

### 5.3 The `AddressMap`

Each domain holds an `AddressMap` that records every GPA↔HPA mapping:

```rust
/// Per-domain address translation bookkeeping.
pub struct AddressMap {
    /// GPA-start → mapping entry, sorted for efficient lookup and gap detection.
    /// Includes both active mappings and blocked entries (carved-away gaps).
    entries: BTreeMap<u64, MapEntry>,
}

enum MapEntry {
    /// Active mapping: this GPA range is mapped to an HPA range.
    Mapped(MappingEntry),
    /// Blocked: this GPA range is reserved (carved-away gap in parent).
    /// Cannot be reused until the child is revoked and the parent regains it.
    Blocked { size: u64 },
}

struct MappingEntry {
    hpa_start: u64,
    gpa_start: u64,
    size: u64,           // mapped size (may be < HPA range if color-filtered)
    rights: Rights,      // access rights for this mapping (tracked per §5.2)
    color_bitmap: Option<ColorBitmap>,
}
```

Free GPA ranges are not tracked explicitly — they are derived as the gaps
between entries in the sorted `BTreeMap`.  When allocating a GPA for a new
mapping without a hint, the map scans for the first gap large enough.

**Allocation strategy**: when a `GpaHint` is provided, the `AddressMap`
checks that the requested range does not overlap any existing entry
(mapped or blocked) and rejects the operation if it does.  When no hint is
provided, the default is **identity mapping** (GPA == HPA), recorded in the
`AddressMap` like any other translation.

**Root domain**: the root domain has an `AddressMap` like any other domain.
At initialisation, `r0` is inserted with identity-mapped GPA (or a
platform-provided base).  This allows the platform to relocate the root
domain in physical memory if needed.

**Lifecycle**:
- `insert(hpa_start, size, rights, color_bitmap, hint) → gpa_start` — register a new mapping
- `split(hpa_range, new_rights)` — split an existing entry at the given sub-range with different rights (used at carve time)
- `block(hpa_range)` — transition a `Mapped` entry to `Blocked` (used at send time; entry must already be its own entry from a prior split)
- `unblock(hpa_range, rights)` — transition a `Blocked` entry back to `Mapped` (used at revoke time; may coalesce with neighbours)
- `remove(hpa_start) → MappingEntry` — remove on domain revocation
- `translate(hpa, size) → (gpa, size, rights)` — lookup for update emission

### 5.4 Integration Points

#### Domain

When `feature = "address_translation"`:

```rust
pub struct Domain {
    // ... existing fields ...
    #[cfg(feature = "address_translation")]
    pub address_map: AddressMap,
}
```

#### Send / Accept

After the ownership transfer, before emitting updates:

```
send(memory_cap, receiver)
  ├── transfer ownership (existing logic)
  ├── receiver.address_map.insert(hpa, size, colors)  ← NEW
  ├── compute view_diff → updates
  └── fixup_updates(updates, sender.address_map, receiver.address_map)  ← NEW
```

The `fixup_updates` pass rewrites the `address` field in each `ChangeRights`
by looking up the domain's `AddressMap`:

```rust
fn fixup_updates(batch: &mut UpdateBatch, maps: &HashMap<DomainId, &AddressMap>) {
    for update in batch.updates_mut() {
        if let Update::ChangeRights { domain, address, physical, .. } = update {
            *physical = *address;  // address is currently HPA (identity)
            if let Some(map) = maps.get(domain) {
                *address = map.translate(*physical);
            }
        }
    }
}
```

#### Revoke

During `revoke_subtree`, when emitting unmap/remap updates:

- **Unmap child**: use child domain's `AddressMap` to get the GPA.
  Then `child.address_map.remove(hpa)`.
- **Remap parent**: use parent domain's `AddressMap` to get the (still-valid)
  GPA for the restored range.

#### view_diff

`view_diff` currently works entirely in HPA space (since `Access.start` is an
HPA).  Two options:

**Option A — Post-process**: let `view_diff` produce HPA-based updates, then
run `fixup_updates`.  Simple, minimal changes to `view.rs`.

**Option B — Translate inputs**: translate the `AddressSpaceView` regions to
GPA before diffing, so `view_diff` produces GPA-based updates directly.
More correct for edge cases where HPA regions overlap in GPA space.

**Recommendation**: Option A for the initial implementation.  The
`AddressMap` guarantees no GPA aliasing, so the post-processing is
straightforward.

#### AddressMap ↔ Capability Synchronisation

The `AddressMap` must stay in sync with the domain's owned capabilities.
Every operation that changes which HPAs a domain sees must have a
corresponding `AddressMap` mutation:

| Operation | Capability effect | AddressMap effect |
|-----------|-------------------|-------------------|
| `carve` | Parent's view may shrink (if rights attenuated) | **Entry split** if carved rights differ from parent's: parent's entry is split into up to 3 entries (left, carved sub-range with reduced rights, right). See §5.2. |
| `send` carved (to unsealed) | Receiver gains cap; sender loses carved range | `receiver.insert(hpa)`; **sender: entry split + block** (see below) |
| `send` alias (to unsealed) | Receiver gains cap; sender keeps access | `receiver.insert(hpa)`; sender's map unchanged |
| `send` (to sealed → pending) | No immediate view change | No map change yet (deferred to `accept`) |
| `accept` carved | Receiver gains cap and view | `receiver.insert(hpa)`; **sender: entry split + block** (see below) |
| `accept` alias | Receiver gains cap and view | `receiver.insert(hpa)`; sender's map unchanged |
| `reject` | Pending cap discarded | No map change |
| `revoke` (carved child) | Parent regains view | `child_owner.remove(hpa)`; **parent: `Blocked` → `Mapped`** (coalesce with neighbours) |
| `revoke` (alias) | Alias owner loses view | `alias_owner.remove(hpa)` |
| `revoke_domain` | All of domain's memory returned | `domain.address_map` dropped; parent `Blocked` entries restored to `Mapped` |

#### Entry Splitting at Send Time

When a carved sub-region is sent away, the sender's `AddressMap` entry
that covers the carved range must be **split**.  The carved portion becomes
`Blocked`; the surrounding portions remain `Mapped` with their original
GPA→HPA translations.

Example: parent has a single entry `[GPA 0x0..0x40000) → HPA [0x0..0x40000)`.
A carved region `[0x10000..0x20000)` is sent to a child:

```
Before send:
  [0x00000..0x40000) Mapped

After send:
  [0x00000..0x10000) Mapped   ← left fragment
  [0x10000..0x20000) Blocked  ← carved-away, reserved for revocation
  [0x20000..0x40000) Mapped   ← right fragment
```

The left and right fragments retain their original GPA→HPA mapping.  On
revocation of the child, the `Blocked` entry is replaced with `Mapped`
and the three entries may be coalesced back into one.

Note that `carve` itself does **not** split the entry — the parent still
has access to the carved range (potentially with reduced rights, but that
is handled by `ChangeRights` updates from `view_diff`, not by the
`AddressMap`).  The split happens only when ownership actually transfers
via `send` or `accept`.

The key insight is that `AddressMap` mutations are co-located with the
existing ownership-transfer and update-emission code.  They happen inside
the same capability lock, so no additional synchronisation is needed.

### 5.5 Cache-Color Compaction

#### Platform Extension

```rust
pub trait Platform: Send + Sync {
    // ... existing methods ...

    /// Return the page size and number of cache colors for this platform.
    /// Colors are numbered 0..num_colors.  A physical page at address `addr`
    /// has color `(addr / page_size) % num_colors`.
    ///
    /// Returns `None` if the platform is not cache-color aware.
    #[cfg(feature = "address_translation")]
    fn cache_color_info(&self) -> Option<CacheColorInfo> {
        None
    }
}

pub struct CacheColorInfo {
    pub page_size: u64,
    pub num_colors: u32,
}
```

#### Color Bitmap

```rust
/// Bitmap selecting which cache colors are authorized for a capability.
/// Bit `i` set means pages with color `i` are included.
/// Dynamically sized to support platforms with arbitrary color counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColorBitmap {
    bits: Vec<u64>,  // ceil(num_colors / 64) words
}

impl ColorBitmap {
    /// True if color `i` is authorized.
    pub fn contains(&self, color: u32) -> bool { ... }
    /// True if `self` is a subset of `other` (monotonicity check).
    pub fn is_subset_of(&self, other: &ColorBitmap) -> bool { ... }
    /// Number of set bits (= number of authorized pages per color cycle).
    pub fn popcount(&self) -> u32 { ... }
}
```

#### Compaction in `AddressMap::insert`

When a colored capability is inserted:

```
HPA range: [0x100000 .. 0x140000)   (256 KB, 64 pages at 4 KB)
Colors:    bitmap 0b1010             (colors 1 and 3 only)
Platform:  page_size=4096, num_colors=4

Authorized pages:  those where (page_number % 4) ∈ {1, 3}
                   = pages 1, 3, 5, 7, 9, 11, ... (32 out of 64)

GPA allocation:    [next_gpa .. next_gpa + 32*4096)  ← contiguous

Translation table:
  HPA 0x101000 → GPA next_gpa + 0x0000   (color 1)
  HPA 0x103000 → GPA next_gpa + 0x1000   (color 3)
  HPA 0x105000 → GPA next_gpa + 0x2000   (color 1)
  ...
```

The domain sees a contiguous 128 KB region.  The monitor's EPT maps each
GPA page to the correct HPA page.  The `ChangeRights` updates carry these
per-page GPA→HPA pairs.

#### Update Emission for Colored Regions

For colored regions, a single `ChangeRights` with `(gpa, size, hpa)` is
insufficient — the mapping is non-contiguous in HPA space.

The engine emits a **single update** carrying the color bitmap.  The
`Platform::apply_update` implementation iterates the authorized pages
internally, avoiding a state explosion of many small `ChangeRights` for
large regions with many colors.

The `ChangeRights` variant is extended with an optional color bitmap:

```rust
ChangeRights {
    domain: DomainId,
    address: u64,            // GPA start (contiguous in guest space)
    size: u64,               // full HPA range size
    physical: u64,           // HPA start
    rights: Rights,
    shootdown_required: bool,
    #[cfg(feature = "address_translation")]
    colors: Option<ColorBitmap>,  // which pages within the range to map
}
```

When `colors` is `Some`, the platform applies the mapping page-by-page,
advancing through the HPA range and skipping pages whose color is not in
the bitmap, while mapping authorized pages at consecutive GPAs:

```
fn apply_colored_map(gpa: u64, hpa: u64, full_size: u64, colors: &ColorBitmap) {
    let mut cur_hpa = hpa;
    let mut cur_gpa = gpa;
    let hpa_end = hpa + full_size;
    while cur_hpa < hpa_end {
        if colors.contains(page_color(cur_hpa)) {
            map_page(cur_gpa, cur_hpa);
            cur_gpa += PAGE_SIZE;
        }
        cur_hpa += PAGE_SIZE;
    }
}
```

When `colors` is `None`, the update behaves exactly as today — a single
contiguous mapping.

---

## 6. Data-Model Changes

### 6.1 `MemoryRegion` (memory.rs)

```rust
pub struct MemoryRegion {
    pub kind: RegionKind,
    pub status: RegionStatus,
    pub access: Access,
    #[cfg(feature = "address_translation")]
    pub color_bitmap: Option<ColorBitmap>,
}
```

The color bitmap is set at `carve` / `alias` time (optional parameter) and
must satisfy monotonicity: `child.colors ⊆ parent.colors`.

### 6.2 `Domain` (domain.rs)

```rust
pub struct Domain {
    // ... existing fields ...
    #[cfg(feature = "address_translation")]
    pub address_map: AddressMap,
}
```

### 6.3 `Update` (update.rs)

The `ChangeRights` variant gains an optional `ColorBitmap` field behind the
feature gate:

```rust
ChangeRights {
    domain: DomainId,
    address: u64,
    size: u64,
    physical: u64,
    rights: Rights,
    shootdown_required: bool,
    #[cfg(feature = "address_translation")]
    colors: Option<ColorBitmap>,
}
```

When the feature is absent, the struct is unchanged.  When present but
`colors` is `None`, the update behaves as a single contiguous mapping
(backward compatible).

### 6.4 Attestation

The attestation report includes the GPA base for each memory region when the
feature is active:

```
Memory region:
  HPA: [0x100000..0x140000)
  GPA: [0x200000..0x220000)  ← only present with address_translation
  Rights: RWX
  Colors: 0b1010             ← only present if colored
```

---

## 7. API Surface

### 7.1 Engine API Changes

When `feature = "address_translation"` is active:

```rust
// Carve with optional color bitmap
Capability::carve(caller, parent_handle, access, colors: Option<ColorBitmap>)

// Send with optional GPA hint
Capability::send(caller, mem_handle, target_handle, attrs, gpa_hint: Option<u64>)
```

When the feature is absent, these parameters don't exist and the API is
unchanged.  This can be achieved with a wrapper type:

```rust
#[cfg(feature = "address_translation")]
pub struct TranslationParams {
    pub color_bitmap: Option<ColorBitmap>,
    pub gpa_hint: Option<u64>,
}
```

### 7.2 Platform API Changes

```rust
pub trait Platform: Send + Sync {
    /// Cache color configuration. Returns `None` for non-colored platforms.
    #[cfg(feature = "address_translation")]
    fn cache_color_info(&self) -> Option<CacheColorInfo> { None }
}
```

---

## 8. Invariants

The translation layer must maintain these invariants at all times:

| ID | Invariant | Enforced at |
|----|-----------|-------------|
| T1 | No HPA appears twice in a domain's GPA space | `AddressMap::insert` |
| T2 | No GPA is mapped to two different HPAs | `AddressMap::insert` |
| T3 | A carved-away HPA range has no GPA mapping in the parent | `send` + `AddressMap` gap tracking |
| T4 | Child color bitmap ⊆ parent color bitmap | `carve` / `alias` validation |
| T5 | GPA range for a colored region = `page_size × popcount(authorized pages)` | `AddressMap::insert` compaction |
| T6 | On revocation, parent's GPA mapping is restored to its pre-send state | `revoke_subtree` + `AddressMap::remove` + re-insert |

---

## 9. Interaction with Concurrency (Loom)

The `AddressMap` is stored inside `Domain`, which is behind `RwLock`.
Translation lookups happen inside the existing capability lock (shared or
exclusive), so no additional synchronisation is needed.

The loom test suite should gain at least one test that exercises concurrent
`send` + `revoke` with translation enabled to verify that `AddressMap`
mutations are properly serialised.

---

## 10. Implementation Plan

| Phase | Scope | Depends on |
|-------|-------|------------|
| **P1** | Feature gate + `AddressMap` struct + `translate()` + unit tests | — |
| **P2** | Hook into `send` / `accept` / `revoke` update emission | P1 |
| **P3** | `view_diff` post-processing (`fixup_updates`) | P2 |
| **P4** | Attestation: include GPA in report | P2 |
| **P5** | `ColorBitmap` + compaction logic in `AddressMap` | P1 |
| **P6** | Platform trait extension (`cache_color_info`) | P5 |
| **P7** | `carve` / `alias` color bitmap parameter + monotonicity | P5 |
| **P8** | CLI support (display GPA, color options) | P3, P4 |
| **P9** | Loom concurrency tests with translation | P3 |

---

## 11. Design Decisions

The following questions were resolved during design review:

| # | Question | Decision | Rationale |
|---|----------|----------|-----------|
| 1 | GPA allocation: bump or recycle? | **Recycle** — freed GPAs may be reused | Avoids address-space exhaustion; invariants (e.g. carved-gap exclusion) prevent unsafe reuse |
| 2 | Root domain `AddressMap`? | **Yes** — root has an `AddressMap` | Enables platform-level relocation of the root domain in physical memory |
| 3 | Alias GPA sharing across domains? | **Independent GPAs** per domain | Simpler, more isolated; each domain's `AddressMap` is self-contained |
| 4 | Colored-region update granularity? | **Single update** with color bitmap; platform iterates pages | Avoids state explosion for large colored regions; platform knows page size |
| 5 | Color bitmap width? | **Dynamically sized** (`Vec<u64>`) | Some platforms have more than 64 colors |
| 6 | Free-list data structure? | **No explicit free-list** — derive free ranges from occupied entries | The `AddressMap` tracks all taken GPAs; free ranges are the gaps. When a carved region is **sent** (not at carve time — the parent retains access until send), its GPA entry transitions from `Mapped` to `Blocked`, preventing reuse until revocation restores it. |
| 7 | GPA hint conflicts? | **Reject the operation** — caller is responsible for choosing a valid GPA | If no hint is provided, default to identity mapping (GPA == HPA) and record the translation in the `AddressMap`. |
| 8 | `no_std` compatibility? | **Use `alloc`** for `Vec<u64>` in `ColorBitmap` | The engine already depends on `alloc`; no new dependency. |
| 9 | Should `AddressMap` track rights? | **Yes (Option B)** — each `MappingEntry` carries `Rights` | Self-contained view of GPA space; carve-time splits make send-time blocking trivial; enables leaner locking (no capability tree re-lock for translation). Option A (translation only) rejected — see §5.2. |

### Remaining Open Questions

All resolved — see decisions 6–8 above.
