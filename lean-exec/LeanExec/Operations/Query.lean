/-
  LeanExec.Operations.Query — Query and attestation operations.

  Implements computeAddressSpace, enumeratePending, attest, and
  attestSelf for inspecting domain state without modification.
-/
import LeanExec.Monad

namespace LeanExec

open ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Helpers — range subtraction for address space computation
-- ════════════════════════════════════════════════════════════════════

/-- Subtract a single range [cs, ce) from a list of segments,
    producing the remaining visible portions. -/
private def subtractOne (segments : List (Nat × Nat)) (cs ce : Nat)
    : List (Nat × Nat) :=
  segments.flatMap fun (s, sz) =>
    let e := s + sz
    if ce ≤ s || cs ≥ e then [(s, sz)]
    else
      let before := if cs > s then [(s, cs - s)] else []
      let after  := if ce < e then [(ce, e - ce)] else []
      before ++ after

/-- Subtract a list of carved ranges from a base range. -/
private def subtractRanges (start : Nat) (size : Nat)
    (carved : List (Nat × Nat)) : List (Nat × Nat) :=
  carved.foldl (fun segs (cs, csz) => subtractOne segs cs (cs + csz)) [(start, size)]

-- ════════════════════════════════════════════════════════════════════
-- § computeAddressSpace — merged address space view
-- ════════════════════════════════════════════════════════════════════

/-- Get the merged address space view for a domain.

    Returns (gpa, size, hpa, rights) tuples representing visible memory.
    GPA offsets from gpaOverrides are applied so entries reflect the
    domain's actual address space layout, not raw HPAs. -/
def computeAddressSpace (domId : DomainId) (excludeMeta : Bool := false)
    : CapaM (List (Nat × Nat × Nat × Rights)) := do
  let dom ← CapaM.getDomain domId
  let s ← CapaM.getState
  let entries := dom.memCaps.filterMap fun (_, uid) =>
    match s.getMemCap uid with
    | some cap =>
      -- META caps excluded from the domain's EPT view (used by `view` command)
      -- but included in the attest GPA section (matching Rust address_map)
      if excludeMeta && cap.attributes.meta then none
      else
      let access := cap.region.access
      let carvedRanges := cap.childUids.toList.filterMap fun childUid =>
        match s.getMemCap childUid with
        | some child =>
          if child.region.kind == .carve then
            some (child.region.access.start, child.region.access.size)
          else none
        | none => none
      let segments := subtractRanges access.start access.size carvedRanges
      -- Apply GPA offset from domain's overrides
      let gpaBase := match dom.gpaOverrides.find? (fun p => p.1 == uid) with
        | some (_, g) => g
        | none => access.start
      let gpaOffset := gpaBase - access.start
      some (segments.map fun (st, sz) => (st + gpaOffset, sz, st, access.rights))
    | none => none
  pure (entries.flatten.mergeSort fun a b => a.1 < b.1)

-- ════════════════════════════════════════════════════════════════════
-- § computeAttestAddressMap — attest-report address map
-- ════════════════════════════════════════════════════════════════════

/-- Address map entry for the attest report's GPA Address Space section. -/
inductive AttestAddrEntry where
  | mapped  (gpa : Nat) (size : Nat) (hpa : Nat) (rights : Rights)
  | blocked (gpa : Nat) (size : Nat) (hpa : Nat)

/-- GPA of an address map entry (for sorting). -/
private def AttestAddrEntry.gpa : AttestAddrEntry → Nat
  | .mapped g _ _ _ => g
  | .blocked g _ _  => g

/-- Split (gpa, size, hpa, rights) segments at boundary points.
    Each point that falls strictly inside a segment splits it into two,
    preserving GPA–HPA correspondence. -/
private def splitSegmentsAtPoints
    (segments : List (Nat × Nat × Nat × Rights))
    (points : List Nat) : List (Nat × Nat × Nat × Rights) :=
  points.foldl (fun segs pt =>
    segs.flatMap fun (gpa, sz, hpa, r) =>
      let gpaEnd := gpa + sz
      if pt > gpa && pt < gpaEnd then
        [(gpa, pt - gpa, hpa, r),
         (pt, gpaEnd - pt, hpa + (pt - gpa), r)]
      else
        [(gpa, sz, hpa, r)]
  ) segments

/-- Compute address-map-style entries for the attest report.

    Mirrors the Rust engine's AddressMap which tracks per-capability
    footprints with carved-child blocking and alias-boundary splitting.

    Top-level caps are owned memcaps whose parent is either absent (root cap)
    or owned by a different domain (received via send/accept).  Non-top-level
    caps (children of other owned memcaps) are skipped — their footprints
    are accounted for by the parent's split processing. -/
def computeAttestAddressMap (domId : DomainId)
    : CapaM (List AttestAddrEntry) := do
  let dom ← CapaM.getDomain domId
  let s ← CapaM.getState
  let allEntries : List AttestAddrEntry := dom.memCaps.flatMap fun (_, uid) =>
    match s.getMemCap uid with
    | none => []
    | some cap =>
      -- Determine if this is a top-level cap (root or received from outside)
      let isRootCap := cap.parentUid.isNone
      let isReceivedFromOutside := match cap.parentUid with
        | none => false
        | some puid =>
          match s.getMemCap puid with
          | some parent => parent.capId.domainId != domId
          | none => true
      let isTopLevel := isRootCap || isReceivedFromOutside
      if !isTopLevel then []
      else
        let access := cap.region.access
        -- Compute GPA offset from domain's overrides
        let gpaBase := match dom.gpaOverrides.find? (fun p => p.1 == uid) with
          | some (_, g) => g
          | none => access.start
        let gpaOffset := gpaBase - access.start
        match cap.parentUid with
        | none =>
          -- Root cap: only children contribute to the address map.
          cap.childUids.toList.filterMap fun childUid =>
            match s.getMemCap childUid with
            | none => none
            | some child =>
              let cAccess := child.region.access
              if child.capId.domainId == domId then
                some (.mapped (cAccess.start + gpaOffset) cAccess.size
                              cAccess.start cAccess.rights)
              else if child.region.kind == .carve then
                some (.blocked (cAccess.start + gpaOffset) cAccess.size
                               cAccess.start)
              else
                none
        | some _ =>
          -- Received cap: include its footprint, subtract carved children,
          -- split at alias boundaries, and emit BLOCKED for sent carved children.
          let carvedRanges := cap.childUids.toList.filterMap fun childUid =>
            match s.getMemCap childUid with
            | some child =>
              if child.region.kind == .carve then
                some (child.region.access.start, child.region.access.size)
              else none
            | none => none
          let visible := subtractRanges access.start access.size carvedRanges
          let segments := visible.map fun (st, sz) =>
            (st + gpaOffset, sz, st, access.rights)
          -- Collect alias boundary points for splitting
          let aliasPoints := cap.childUids.toList.flatMap fun childUid =>
            match s.getMemCap childUid with
            | some child =>
              if child.region.kind == .alias then
                let cStart := child.region.access.start + gpaOffset
                let cEnd := cStart + child.region.access.size
                [cStart, cEnd]
              else []
            | none => []
          let split := splitSegmentsAtPoints segments aliasPoints
          let mappedEntries := split.map fun (gpa, sz, hpa, r) =>
            AttestAddrEntry.mapped gpa sz hpa r
          -- BLOCKED entries for carved children sent to other domains
          let blockedEntries := cap.childUids.toList.filterMap fun childUid =>
            match s.getMemCap childUid with
            | some child =>
              if child.region.kind == .carve && child.capId.domainId != domId then
                let cAccess := child.region.access
                some (AttestAddrEntry.blocked
                  (cAccess.start + gpaOffset) cAccess.size cAccess.start)
              else none
            | none => none
          mappedEntries ++ blockedEntries
  pure (allEntries.mergeSort fun a b => a.gpa < b.gpa)

-- ════════════════════════════════════════════════════════════════════
-- § enumeratePending — list pending capabilities
-- ════════════════════════════════════════════════════════════════════

/-- List all pending memory and domain capability transfers for a domain. -/
def enumeratePending (domId : DomainId)
    : CapaM (List PendingMemCap × List PendingDomCap) := do
  let dom ← CapaM.getDomain domId
  pure (dom.pendingMem, dom.pendingDom)

-- ════════════════════════════════════════════════════════════════════
-- § attest / attestSelf / attestReport — attestation
-- ════════════════════════════════════════════════════════════════════

/-- Compute attestation for a target domain.

    Preconditions: caller sealed, has ATTEST API, target sealed.
    Returns a simple deterministic hash of the domain ID + memory count. -/
def attest (callerId : DomainId) (targetHandle : LocalHandle)
    : CapaM Nat := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canAttest)
  let targetId ← match caller.lookupDomId targetHandle with
    | some id => pure id
    | none    => CapaM.throw .notFound
  let target ← CapaM.getDomain targetId
  CapaM.requireSealed target
  pure (targetId * 997 + target.memCaps.length * 31)

-- ── Report formatting helpers ───────────────────────────────────────

private def toHexR (n : Nat) : String := s!"0x{String.ofList (Nat.toDigits 16 n)}"

/-- Format a RegBitmap (list of 3 u64 words) as hex, matching Rust LowerHex.
    Prints word[2]:word[1]:word[0] big-endian, skipping leading zero words. -/
private def regBitmapToHex (words : List Nat) : String :=
  let w0 := words.getD 0 0
  let w1 := words.getD 1 0
  let w2 := words.getD 2 0
  if w0 == 0 && w1 == 0 && w2 == 0 then "0x0"
  else
    -- Combine into one big Nat: w2 << 128 | w1 << 64 | w0
    let combined := w2 * (2^128) + w1 * (2^64) + w0
    s!"0x{String.ofList (Nat.toDigits 16 combined)}"

private def coresToBinaryStr (cores : CoreMask) : String :=
  if cores.isEmpty then "0b0"
  else
    let maxCore := cores.foldl max 0
    let bits := (List.range (maxCore + 1)).reverse.map fun i =>
      if cores.contains i then '1' else '0'
    "0b" ++ String.mk bits

private def visToString : VectorPolicy → String
  | .deliver => "Deliver"
  | .deliverAndClear => "Report"
  | .deny => "NotReport"

/-- Pipe-separated attribute string for attest reports (Rust engine Display uses '|'). -/
private def attrsToAttestStr (a : Attributes) : String :=
  let parts := #[]
    |> (if a.hash then (·.push "HASH") else id)
    |> (if a.clean then (·.push "CLEAN") else id)
    |> (if a.vital then (·.push "VITAL") else id)
    |> (if a.meta then (·.push "META") else id)
    |> (if a.comm then (·.push "COMM") else id)
  if parts.isEmpty then "" else "|".intercalate parts.toList

-- ── Naming context for attestation ──────────────────────────────────

/-- Context carried through recursive attestation; assigns sequential names
    dN / chN / mN to domains / channels / memory regions as they are
    first encountered.  Keys are DomainId or CapNodeId (both Nat). -/
structure AttestCtx where
  domNames : List (DomainId × String)   := []
  memNames : List (CapNodeId × String)  := []
  domCtr   : Nat := 0
  memCtr   : Nat := 0
  chCtr    : Nat := 0

private def AttestCtx.nameDomain (ctx : AttestCtx) (did : DomainId)
    (isChan : Bool := false) : AttestCtx × String :=
  match ctx.domNames.find? fun (k, _) => k == did with
  | some (_, n) => (ctx, n)
  | none =>
    let (name, ctx') := if isChan then
      (s!"ch{ctx.chCtr}", { ctx with chCtr := ctx.chCtr + 1 })
    else
      (s!"d{ctx.domCtr}", { ctx with domCtr := ctx.domCtr + 1 })
    ({ ctx' with domNames := ctx'.domNames ++ [(did, name)] }, name)

private def AttestCtx.getDomainName (ctx : AttestCtx) (did : DomainId) : String :=
  match ctx.domNames.find? fun (k, _) => k == did with
  | some (_, n) => n
  | none => "?"

private def AttestCtx.nameMem (ctx : AttestCtx) (uid : CapNodeId) : AttestCtx × String :=
  match ctx.memNames.find? fun (k, _) => k == uid with
  | some (_, n) => (ctx, n)
  | none =>
    let name := s!"m{ctx.memCtr}"
    ({ ctx with memNames := ctx.memNames ++ [(uid, name)], memCtr := ctx.memCtr + 1 }, name)

private def AttestCtx.getMemName (ctx : AttestCtx) (uid : CapNodeId) : String :=
  match ctx.memNames.find? fun (k, _) => k == uid with
  | some (_, n) => n
  | none => "?"

/-- Get or create a channel name (chN) for a target domain. -/
private def AttestCtx.nameChan (ctx : AttestCtx) (targetId : DomainId) : AttestCtx × String :=
  ctx.nameDomain targetId (isChan := true)

private def AttestCtx.getChanName (ctx : AttestCtx) (targetId : DomainId) : String :=
  -- Look for channel name; fall back to "?"
  match ctx.domNames.find? fun (k, _) => k == targetId with
  | some (_, n) => n
  | none => "?"

/-- Pre-name all carved/aliased children of a memory cap (recursive). -/
private partial def nameMemChildren (s : ExecState) (ctx : AttestCtx)
    (uid : CapNodeId) : AttestCtx :=
  match s.getMemCap uid with
  | none => ctx
  | some cap =>
    cap.childUids.toList.foldl (fun acc childUid =>
      let (acc', _) := acc.nameMem childUid
      nameMemChildren s acc' childUid) ctx

-- ── attestWithCtx — format one domain's section ────────────────────

/-- Format a single domain's attestation section.  When `expandChildren`
    is true, child domains are recursively appended (one level deep). -/
private partial def attestWithCtx (domId : DomainId) (ctx : AttestCtx)
    (expandChildren : Bool) : CapaM (String × AttestCtx) := do
  let dom ← CapaM.getDomain domId
  let s ← CapaM.getState

  -- 0. Find channels targeting this domain (like Rust CDT children).
  --    In Rust, channel caps are CDT children of their target domain.
  --    In Lean, channels are in their owner's chanCaps, so we scan.
  let channelsTargetingMe : List (DomainId × LocalHandle) :=
    s.domains.foldl (fun acc (_, otherDom) =>
      otherDom.chanCaps.foldl (fun acc2 (handle, targetId) =>
        if targetId == domId then acc2 ++ [(otherDom.domainId, handle)] else acc2
      ) acc
    ) []

  -- 1. Name this domain (already named by caller)
  let domName := ctx.getDomainName domId

  -- 2. Name owned domain caps
  let ctx := dom.domCaps.foldl (fun acc (_, childId) =>
    let (acc', _) := acc.nameDomain childId
    acc') ctx

  -- 2b. Name channels targeting this domain (get chN names, like Rust CDT children)
  --    Each channel gets a unique chN name based on the counter.
  let (ctx, chanTargetNames) := channelsTargetingMe.foldl (fun (acc, names) _ =>
    let name := s!"ch{acc.chCtr}"
    ({ acc with chCtr := acc.chCtr + 1 }, names ++ [name])
  ) (ctx, ([] : List String))

  -- 3. Name owned memory caps
  let ctx := dom.memCaps.foldl (fun acc (_, uid) =>
    let (acc', _) := acc.nameMem uid
    acc') ctx

  -- 4. Pre-name carved/aliased children of owned memory
  let ctx := dom.memCaps.foldl (fun acc (_, uid) =>
    nameMemChildren s acc uid) ctx

  -- Summary header: d0 = Sealed domain(d1, ?, m0, m1)
  --   domain_caps → named children; chanCaps → "?" (unnamed like Rust)
  let domCapSummary := dom.domCaps.map fun (_, childId) =>
    ctx.getDomainName childId
  let chanCapSummary := dom.chanCaps.map fun _ => "?"
  let memCapSummary := dom.memCaps.map fun (_, uid) =>
    ctx.getMemName uid
  let summary := domCapSummary ++ chanCapSummary ++ memCapSummary
  let summaryStr := ", ".intercalate summary

  let mut out := ""
  out := out ++ s!"{domName} = {dom.status} domain({summaryStr})\n"
  out := out ++ s!"Domain ID: {dom.domainId}\n"
  out := out ++ s!"Status: {dom.status}\n"
  out := out ++ s!"Cores: {coresToBinaryStr dom.policy.cores}\n"

  -- API flags
  out := out ++ "API:\n"
  out := out ++ s!"  CREATE: {dom.policy.api.canCreate}\n"
  out := out ++ s!"  SET: {dom.policy.api.canSet}\n"
  out := out ++ s!"  GET: {dom.policy.api.canGet}\n"
  out := out ++ s!"  SEND: {dom.policy.api.canSend}\n"
  out := out ++ s!"  SEAL: {dom.policy.api.canSeal}\n"
  out := out ++ s!"  ATTEST: {dom.policy.api.canAttest}\n"
  out := out ++ s!"  ENUMERATE: {dom.policy.api.canEnumerate}\n"
  out := out ++ s!"  SWITCH: {dom.policy.api.canSwitch}\n"
  out := out ++ s!"  ALIAS: {dom.policy.api.canAlias}\n"
  out := out ++ s!"  CARVE: {dom.policy.api.canCarve}\n"
  out := out ++ s!"  REVOKE: {dom.policy.api.canRevoke}\n"
  out := out ++ s!"  GETCHAN: {dom.policy.api.canGetChan}\n"
  out := out ++ s!"  RECEIVE_AFTER_SEAL: {dom.policy.api.canReceiveAfterSeal}\n"

  -- Interrupt policy: Lean doesn't model read/write sets.
  -- Root gets read=0x0, write=0x0; children get all-1s (matching Rust defaults).
  let readWrite := if dom.parentDomId.isNone then "0x0"
    else "0xffffffffffffffffffffffffffffffffffffffffffffffff"
  out := out ++ "Interrupts:\n"
  let defVis := visToString dom.policy.interrupts.defaultPolicy
  out := out ++ s!"  Default: visibility={defVis}, read={readWrite}, write={readWrite}\n"
  let overrideLines := dom.policy.interrupts.perVector.map fun (vec, pol) =>
    s!"    Vector {toHexR vec}: visibility={visToString pol}, read={readWrite}, write={readWrite}\n"
  if overrideLines.isEmpty then
    out := out ++ "  Overrides: (none)\n"
  else
    out := out ++ "  Overrides:\n"
    out := out ++ String.join overrideLines

  -- CPUID interposition policy
  let cpuidDefault := match dom.policy.cpuid.default with
    | .trap => "Trap" | .native => "Native"
  out := out ++ "CPUID Policy:\n"
  out := out ++ s!"  Default: {cpuidDefault}\n"
  if dom.policy.cpuid.overrides.isEmpty then
    out := out ++ "  Overrides: (none)\n"
  else
    out := out ++ "  Overrides:\n"
    for ovr in dom.policy.cpuid.overrides do
      match ovr with
      | .trap s e => out := out ++ s!"    {toHexR s}..={toHexR e}: Trap\n"
      | .native s e => out := out ++ s!"    {toHexR s}..={toHexR e}: Native\n"
      | .emulate s e _ => out := out ++ s!"    {toHexR s}..={toHexR e}: Emulate(...)\n"

  -- MSR interposition policy
  let msrDefault := match dom.policy.msrs.default with
    | .trap => "Trap" | .native => "Native"
  out := out ++ "MSR Policy:\n"
  out := out ++ s!"  Default: {msrDefault}\n"
  if dom.policy.msrs.overrides.isEmpty then
    out := out ++ "  Overrides: (none)\n"
  else
    out := out ++ "  Overrides:\n"
    for ovr in dom.policy.msrs.overrides do
      match ovr with
      | .trap s e => out := out ++ s!"    {toHexR s}..={toHexR e}: Trap\n"
      | .native s e => out := out ++ s!"    {toHexR s}..={toHexR e}: Native\n"
      | .emulate s e _ => out := out ++ s!"    {toHexR s}..={toHexR e}: Emulate(...)\n"

  -- Exit policy
  let exitActionStr := fun (a : ExitAction) =>
    let actionStr := if a.trap then "Trap" else "Local"
    let readStr := regBitmapToHex a.readSet
    let writeStr := regBitmapToHex a.writeSet
    s!"action={actionStr}, read={readStr}, write={writeStr}"
  out := out ++ "Exit Policy:\n"
  out := out ++ s!"  Default: {exitActionStr dom.policy.exits.default}\n"
  if dom.policy.exits.overrides.isEmpty then
    out := out ++ "  Overrides: (none)\n"
  else
    out := out ++ "  Overrides:\n"
    for (reason, action) in dom.policy.exits.overrides do
      out := out ++ s!"    Reason {reason}: {exitActionStr action}\n"

  -- Children + parent (includes CDT children + channels targeting this domain)
  out := out ++ s!"Children: {dom.domCaps.length + channelsTargetingMe.length}\n"
  out := out ++ (match dom.parentDomId with
    | some pid => s!"Parent Domain ID: {pid}\n"
    | none => "Parent: None (root domain)\n")

  -- Owned Domain Capabilities
  out := out ++ "\nOwned Domain Capabilities:\n"
  if dom.domCaps.isEmpty && dom.chanCaps.isEmpty then
    out := out ++ "  (none)\n"
  else
    let dcLines := dom.domCaps.map fun (handle, childId) =>
      s!"  Handle {handle}: {ctx.getDomainName childId}\n"
    let chLines := dom.chanCaps.map fun (handle, _targetId) =>
      s!"  Handle {handle}: ? = Channel → ?\n"
    out := out ++ String.join dcLines
    out := out ++ String.join chLines

  -- Owned Memory Capabilities
  out := out ++ "\nOwned Memory Capabilities:\n"
  if dom.memCaps.isEmpty then
    out := out ++ "  (none)\n"
  else
    let mcLines := dom.memCaps.map fun (handle, uid) =>
      let memName := ctx.getMemName uid
      match s.getMemCap uid with
      | some cap =>
        let access := cap.region.access
        let kindStr := toString cap.region.kind
        let attrsStr := attrsToAttestStr cap.attributes
        let mainLine := s!"  Handle {handle}: {memName} = [{toHexR access.start}..{toHexR access.end}) {access.rights} (kind: {kindStr}, attrs: {attrsStr})\n"
        -- GPA line: show for all domains.  Root memcaps have identity
        -- mappings through child footprints in the address map.
        let gpaLine :=
          let gpaBase := match dom.gpaOverrides.find? (fun p => p.1 == uid) with
            | some (_, g) => g
            | none => access.start
          if gpaBase != access.start then
            s!"    GPA: {toHexR gpaBase} (HPA {toHexR access.start})\n"
          else
            s!"    GPA: {toHexR access.start} (identity)\n"
        -- Child carved/aliased lines
        let childLines := cap.childUids.toList.map fun childUid =>
          match s.getMemCap childUid with
          | some child =>
            let childName := ctx.getMemName childUid
            let op := if child.region.kind == .carve then "carved" else "aliased"
            s!"    | {op} at {toHexR child.region.access.start} size {toHexR child.region.access.size} {child.region.access.rights} for {childName}\n"
          | none => ""
        mainLine ++ gpaLine ++ String.join childLines
      | none =>
        s!"  Handle {handle}: {memName} = <not found>\n"
    out := out ++ String.join mcLines

  -- GPA Address Space: computed from the address map for all domains
  let addrMap ← computeAttestAddressMap domId
  out := out ++ "\nGPA Address Space:\n"
  if addrMap.isEmpty then
    out := out ++ "  (empty)\n"
  else
    let gpaLines := addrMap.map fun
      | .mapped gpa size hpa rights =>
        let end_ := gpa + size
        if gpa == hpa then
          s!"  GPA {toHexR gpa}..{toHexR end_} → HPA {toHexR hpa} {rights} (identity)\n"
        else
          s!"  GPA {toHexR gpa}..{toHexR end_} → HPA {toHexR hpa} {rights} \n"
      | .blocked gpa size hpa =>
        let end_ := gpa + size
        s!"  GPA {toHexR gpa}..{toHexR end_} → BLOCKED (HPA {toHexR hpa})\n"
    out := out ++ String.join gpaLines

  -- Recursive child expansion (one level)
  if expandChildren then
    let init : String × AttestCtx := ("", ctx)
    let childSections ← dom.domCaps.foldlM (init := init)
      fun acc entry => do
        let accOut := acc.1
        let accCtx := acc.2
        let childId := entry.2
        let result ← attestWithCtx childId accCtx false
        pure (accOut ++ "\n" ++ result.1, result.2)
    -- Channel expansion: channels targeting this domain (like Rust CDT children)
    -- chanTargetNames[i] pairs with channelsTargetingMe[i]
    let chanSections ← (channelsTargetingMe.zip chanTargetNames).foldlM (init := childSections)
      fun acc ((_ownerId, _handle), chanName) => do
        let accOut := acc.1
        let accCtx := acc.2
        -- Name the target domain (this domain) for the channel line
        let targetName := accCtx.getDomainName domId
        pure (accOut ++ s!"\n{chanName} = Channel → {targetName}\n", accCtx)
    out := out ++ chanSections.1
    pure (out, chanSections.2)
  else
    pure (out, ctx)

-- ── attestReport — full domain report matching Rust output ──────────

/-- Full attestation report for a domain.
    Produces the same multi-section format as Rust's `attest_with_context`.
    Includes the attested domain and all its child domains (one level deep). -/
def attestReport (domId : DomainId) : CapaM String := do
  let dom ← CapaM.getDomain domId
  if dom.isSealed then
    CapaM.guard dom.policy.api.canAttest .permissionDenied
  -- Initialise naming context; name root domain as d0.
  let (ctx, _) := AttestCtx.nameDomain {} domId
  let (report, _) ← attestWithCtx domId ctx true
  pure report

/-- Self-attestation: returns full domain report string.
    If sealed, requires ATTEST API permission. -/
def attestSelf (domId : DomainId) : CapaM String :=
  attestReport domId

end LeanExec
