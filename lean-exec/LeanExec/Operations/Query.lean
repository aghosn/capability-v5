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

    Returns (start, size, rights) tuples representing visible memory.
    For each memCap owned by the domain, includes its access range
    minus any carved children. -/
def computeAddressSpace (domId : DomainId) : CapaM (List (Nat × Nat × Rights)) := do
  let dom ← CapaM.getDomain domId
  let s ← CapaM.getState
  let entries := dom.memCaps.filterMap fun (_, uid) =>
    match s.getMemCap uid with
    | some cap =>
      let access := cap.region.access
      let carvedRanges := cap.childUids.toList.filterMap fun childUid =>
        match s.getMemCap childUid with
        | some child =>
          if child.region.kind == .carve then
            some (child.region.access.start, child.region.access.size)
          else none
        | none => none
      let segments := subtractRanges access.start access.size carvedRanges
      some (segments.map fun (st, sz) => (st, sz, access.rights))
    | none => none
  pure (entries.flatten.mergeSort fun a b => a.1 < b.1)

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

  -- 1. Name this domain (already named by caller)
  let domName := ctx.getDomainName domId

  -- 2. Name owned domain caps
  let ctx := dom.domCaps.foldl (fun acc (_, childId) =>
    let (acc', _) := acc.nameDomain childId
    acc') ctx

  -- 3. Name owned memory caps
  let ctx := dom.memCaps.foldl (fun acc (_, uid) =>
    let (acc', _) := acc.nameMem uid
    acc') ctx

  -- 4. Pre-name carved/aliased children of owned memory
  let ctx := dom.memCaps.foldl (fun acc (_, uid) =>
    nameMemChildren s acc uid) ctx

  -- Summary header: d0 = Sealed domain(d1, m0, m1)
  let domCapSummary := dom.domCaps.map fun (_, childId) =>
    ctx.getDomainName childId
  let memCapSummary := dom.memCaps.map fun (_, uid) =>
    ctx.getMemName uid
  let summary := domCapSummary ++ memCapSummary
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

  -- Children + parent
  out := out ++ s!"Children: {dom.domCaps.length}\n"
  out := out ++ (match dom.parentDomId with
    | some pid => s!"Parent Domain ID: {pid}\n"
    | none => "Parent: None (root domain)\n")

  -- Owned Domain Capabilities
  out := out ++ "\nOwned Domain Capabilities:\n"
  if dom.domCaps.isEmpty then
    out := out ++ "  (none)\n"
  else
    let dcLines := dom.domCaps.map fun (handle, childId) =>
      s!"  Handle {handle}: {ctx.getDomainName childId}\n"
    out := out ++ String.join dcLines

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
        -- GPA line (identity mapping)
        let gpaLine := s!"    GPA: {toHexR access.start} (identity)\n"
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

  -- GPA Address Space
  let addrSpace ← computeAddressSpace domId
  out := out ++ "\nGPA Address Space:\n"
  if addrSpace.isEmpty then
    out := out ++ "  (empty)\n"
  else
    let gpaLines := addrSpace.map fun (start, size, rights) =>
      let end_ := start + size
      s!"  GPA {toHexR start}..{toHexR end_} → HPA {toHexR start} {rights} (identity)\n"
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
    out := out ++ childSections.1
    pure (out, childSections.2)
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
