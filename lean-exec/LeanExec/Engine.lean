/-
  LeanExec.Engine — Command dispatch engine.

  Defines the `Command` inductive, `CliState` for name→ID mapping,
  and the `dispatch` function that routes CLI commands to CapaM operations.
-/
import LeanExec.Operations.Memory
import LeanExec.Operations.Domain
import LeanExec.Operations.Channel
import LeanExec.Operations.Switch
import LeanExec.Operations.Policy
import LeanExec.Operations.Query

namespace LeanExec

open ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Command — all CLI commands as a single inductive
-- ════════════════════════════════════════════════════════════════════

inductive Command where
  | init (name : String) (memSize : Nat)
  | createDomain (parent : String) (name : String) (cores : Nat) (api : String)
  | carve (parent : String) (name : String) (start : Nat) (size : Nat) (rights : String)
  | alias_ (parent : String) (name : String) (start : Nat) (size : Nat) (rights : String)
  | send (mem : String) (domain : String) (attrs : String) (gpa : Option Nat)
  | seal (domain : String)
  | revoke (parent : String) (child : String)
  | switchCmd (domain : Option String) (core : Nat) (vpId : Option Nat)
  | interrupt (vector : Nat) (domain : String) (core : Nat)
  | list
  | view (domain : String)
  | enumeratePending (domain : String)
  | acceptCapability (domain : String) (pendingId : Nat) (gpa : Option Nat)
  | rejectCapability (domain : String) (pendingId : Nat)
  | getChan (target : String) (chanName : String)
  | sendChannel (chan : String) (receiver : String)
  | acceptChannel (receiver : String) (pendingId : Nat) (chanName : String)
  | rejectChannel (receiver : String) (pendingId : Nat)
  | registerComm (mem : String) (childDomain : String) (vpId : Nat)
  | setPolicy (parent : String) (child : String) (field : String) (value : Nat)
  | getPolicy (parent : String) (child : String) (field : String)
  | setRegister (parent : String) (child : String) (vpId : Nat) (regId : Nat) (value : Nat)
  | getRegister (parent : String) (child : String) (vpId : Nat) (regId : Nat)
  | attest (domain : String)
  | setInterruptPolicy (domain : String) (vector : Nat) (visibility : Nat)
  | addVp (parent : String) (child : String) (commMem : String) (vpId : Nat)
  | help
  | reset (numCores : Nat)

-- ════════════════════════════════════════════════════════════════════
-- § CliState — tracks name↔ID mappings for the interactive CLI
-- ════════════════════════════════════════════════════════════════════

structure CliState where
  execState   : ExecState
  domainNames : List (String × DomainId)
  memNames    : List (String × CapNodeId)
  chanNames   : List (String × (DomainId × LocalHandle))
  currentCore : Option CoreId

namespace CliState

def empty : CliState :=
  { execState   := ExecState.empty 4
    domainNames := []
    memNames    := []
    chanNames   := []
    currentCore := none }

def lookupDomain (st : CliState) (name : String) : Option DomainId :=
  (st.domainNames.find? (fun p => p.1 == name)).map Prod.snd

def lookupMem (st : CliState) (name : String) : Option CapNodeId :=
  (st.memNames.find? (fun p => p.1 == name)).map Prod.snd

def lookupChan (st : CliState) (name : String) : Option (DomainId × LocalHandle) :=
  (st.chanNames.find? (fun p => p.1 == name)).map Prod.snd

def registerDomain (st : CliState) (name : String) (id : DomainId) : CliState :=
  { st with domainNames := st.domainNames ++ [(name, id)] }

def registerMem (st : CliState) (name : String) (uid : CapNodeId) : CliState :=
  { st with memNames := st.memNames ++ [(name, uid)] }

def registerChan (st : CliState) (name : String) (domId : DomainId) (handle : LocalHandle) : CliState :=
  { st with chanNames := st.chanNames ++ [(name, (domId, handle))] }

end CliState

-- ════════════════════════════════════════════════════════════════════
-- § Helpers — hex formatting, name resolution
-- ════════════════════════════════════════════════════════════════════

private def toHex (n : Nat) : String :=
  if n == 0 then "0" else String.ofList (Nat.toDigits 16 n)

/-- Find a domain's name from its ID. -/
private def domainName (st : CliState) (id : DomainId) : String :=
  match st.domainNames.find? (fun p => p.2 == id) with
  | some (name, _) => name
  | none => s!"dom{id}"

/-- Find the local handle for a memcap UID in a specific domain. -/
private def findMemHandle (dom : ExecDomain) (uid : CapNodeId) : Option LocalHandle :=
  (dom.memCaps.find? (fun p => p.2 == uid)).map Prod.fst

/-- Find the local handle for a child domain ID in a parent's domCaps. -/
private def findDomHandle (parent : ExecDomain) (childId : DomainId) : Option LocalHandle :=
  (parent.domCaps.find? (fun p => p.2 == childId)).map Prod.fst

/-- Parse an API string like "CREATE,SEND,CARVE" into MonitorAPI. -/
def parseApiString (s : String) : MonitorAPI :=
  if s == "ALL" then MonitorAPI.full
  else if s == "NONE" then MonitorAPI.none
  else
    let parts := s.splitOn ","
    { canCreate           := parts.contains "CREATE"
      canSet              := parts.contains "SET"
      canGet              := parts.contains "GET"
      canSend             := parts.contains "SEND"
      canSeal             := parts.contains "SEAL"
      canAttest           := parts.contains "ATTEST"
      canEnumerate        := parts.contains "ENUMERATE"
      canSwitch           := parts.contains "SWITCH"
      canAlias            := parts.contains "ALIAS"
      canCarve            := parts.contains "CARVE"
      canRevoke           := parts.contains "REVOKE"
      canGetChan          := parts.contains "GETCHAN"
      canReceiveAfterSeal := parts.contains "RECEIVE_AFTER_SEAL" }

/-- Parse a rights string like "RWX" or "RW" into Rights. -/
def parseRightsString (s : String) : Rights :=
  { read    := s.contains 'R'
    write   := s.contains 'W'
    execute := s.contains 'X' }

/-- Parse an attributes string like "CLEAN,VITAL" into Attributes. -/
def parseAttrsString (s : String) : Attributes :=
  if s == "NONE" || s == "" then Attributes.empty
  else
    let parts := s.splitOn ","
    { hash  := parts.contains "HASH"
      clean := parts.contains "CLEAN"
      vital := parts.contains "VITAL"
      «meta»  := parts.contains "META"
      comm  := parts.contains "COMM" }

/-- Parse a core mask string (hex number) into a core list. -/
private def parseCoreList (n : Nat) : List Nat :=
  (List.range 64).filter n.testBit

/-- Run a CapaM computation on the current CliState, updating state on success. -/
private def runCapaM (stRef : IO.Ref CliState) (m : CapaM α) : IO (Except CapaError α) := do
  let st ← stRef.get
  let (result, newExecState) := CapaM.run m st.execState
  stRef.modify fun s => { s with execState := newExecState }
  pure result

-- ════════════════════════════════════════════════════════════════════
-- § formatList — pretty-print the full system state
-- ════════════════════════════════════════════════════════════════════

private def formatList (st : CliState) : String := Id.run do
  let s := st.execState
  let mut out := ""
  -- Cores
  out := out ++ "═══ Cores ═══\n"
  for i in [:s.cores.size] do
    let coreState := s.cores[i]!
    let desc := match coreState with
      | .idle => "idle"
      | .runningDomain d v => s!"{domainName st d} (vp {v})"
    out := out ++ s!"  Core {i}: {desc}\n"
  -- Domains
  out := out ++ "═══ Domains ═══\n"
  for (domId, dom) in s.domains do
    let name := domainName st domId
    out := out ++ s!"  [{domId}] {name} — {dom.status}\n"
    out := out ++ s!"    Policy: cores={dom.policy.cores}, api={dom.policy.api}, numVps={dom.policy.numVps}\n"
    out := out ++ s!"    VPs: {dom.vps.size}\n"
    for vp in dom.vps.toList do
      out := out ++ s!"      VP {vp.id}: {vp.runState}\n"
    if !dom.memCaps.isEmpty then
      out := out ++ s!"    MemCaps:\n"
      for (handle, uid) in dom.memCaps do
        match s.getMemCap uid with
        | some cap =>
          let frozen := if dom.isFrozen handle then " [FROZEN]" else ""
          let memName := match st.memNames.find? (fun p => p.2 == uid) with
            | some (n, _) => s!" ({n})"
            | none => ""
          out := out ++ s!"      h{handle} → uid{uid}{memName}: {cap.region.kind} {cap.region.status} [0x{toHex cap.region.access.start}..0x{toHex cap.region.access.end}) {cap.region.access.rights} attrs={cap.attributes}{frozen}\n"
        | none =>
          out := out ++ s!"      h{handle} → uid{uid}: <missing>\n"
    if !dom.domCaps.isEmpty then
      out := out ++ s!"    DomCaps:\n"
      for (handle, childId) in dom.domCaps do
        out := out ++ s!"      h{handle} → {domainName st childId} (id={childId})\n"
    if !dom.chanCaps.isEmpty then
      out := out ++ s!"    ChanCaps:\n"
      for (handle, targetId) in dom.chanCaps do
        out := out ++ s!"      h{handle} → {domainName st targetId} (id={targetId})\n"
    if !dom.pendingMem.isEmpty then
      out := out ++ s!"    PendingMem:\n"
      for pm in dom.pendingMem do
        out := out ++ s!"      pending#{pm.pendingId}: from {domainName st pm.senderDomId} uid={pm.capNodeId} attrs={pm.attributes}\n"
    if !dom.pendingDom.isEmpty then
      out := out ++ s!"    PendingDom:\n"
      for pd in dom.pendingDom do
        out := out ++ s!"      pending#{pd.pendingId}: from {domainName st pd.senderDomId} target={domainName st pd.targetDomId}\n"
    if !dom.commBindings.isEmpty then
      out := out ++ s!"    COMM bindings:\n"
      for (targetDom, vpId, memUid) in dom.commBindings do
        out := out ++ s!"      target={domainName st targetDom} vp={vpId} mem=uid{memUid}\n"
  out

-- ════════════════════════════════════════════════════════════════════
-- § formatView — show a single domain's address space
-- ════════════════════════════════════════════════════════════════════

private def formatView (st : CliState) (domId : DomainId) (addrSpace : List (Nat × Nat × Nat × Rights)) : String := Id.run do
  let name := domainName st domId
  let mut out := s!"Address space for {name} (id={domId}):\n"
  if addrSpace.isEmpty then
    out := out ++ "  <empty>\n"
  else
    for (gpa, size, _hpa, rights) in addrSpace do
      out := out ++ s!"  [0x{toHex gpa}..0x{toHex (gpa + size)}) {rights}\n"
  out

-- ════════════════════════════════════════════════════════════════════
-- § formatUpdates — display HwUpdate batch
-- ════════════════════════════════════════════════════════════════════

private def formatUpdates (updates : UpdateBatch) : String :=
  if updates.isEmpty then ""
  else
    let lines := updates.map (s!"  {·}")
    "  HW updates:\n" ++ "\n".intercalate lines

-- ════════════════════════════════════════════════════════════════════
-- § dispatch — route a Command to the appropriate CapaM operation
-- ════════════════════════════════════════════════════════════════════

def dispatch (stRef : IO.Ref CliState) (cmd : Command) : IO String := do
  match cmd with

  | .init name memSize => do
    let result ← runCapaM stRef (LeanExec.init memSize 4)
    match result with
    | .ok (domId, rootUid) =>
      stRef.modify fun st =>
        let pfx := name.toList.head?.getD 'r'
        let st := st.registerDomain name domId
        let st := st.registerMem s!"{pfx}0" rootUid
        st
      pure s!"Initialized: domain '{name}' (id={domId}), root mem '{name.toList.head?.getD 'r'}0' (uid={rootUid}), size=0x{toHex memSize}"
    | .error e => pure s!"Error: {e}"

  | .createDomain parentName childName cores apiStr => do
    let st ← stRef.get
    let some parentId := st.lookupDomain parentName
      | pure s!"Error: unknown domain '{parentName}'"
    let some _parent := st.execState.getDomain parentId
      | pure s!"Error: domain '{parentName}' not found in state"
    -- Build child policy
    let coreList := parseCoreList cores
    let api := parseApiString apiStr
    let childPolicy : DomainPolicy :=
      { cores := coreList, api := api
        interrupts := { defaultPolicy := .deliverAndClear, perVector := [] }
        numVps := coreList.length }
    let result ← runCapaM stRef (LeanExec.create parentId childPolicy)
    match result with
    | .ok (handle, newId, updates) =>
      stRef.modify (·.registerDomain childName newId)
      let _ := handle  -- handle is internal
      pure s!"Created domain '{childName}' (id={newId}), handle=h{handle} in '{parentName}'\n{formatUpdates updates}"
    | .error e => pure s!"Error: {e}"

  | .carve parentName childName start size rightsStr => do
    let st ← stRef.get
    let some parentId := st.lookupDomain parentName
      | do
        -- Try as memory name: look up the memcap and find its owning domain
        let some parentUid := st.lookupMem parentName
          | pure s!"Error: unknown domain/memory '{parentName}'"
        -- Find owning domain
        let some parentCap := st.execState.getMemCap parentUid
          | pure s!"Error: memcap not found"
        let ownerId := parentCap.capId.domainId
        let some owner := st.execState.getDomain ownerId
          | pure s!"Error: owning domain not found"
        let some handle := findMemHandle owner parentUid
          | pure s!"Error: handle not found for '{parentName}'"
        let rights := parseRightsString rightsStr
        let access : Access := { start := start, size := size, rights := rights }
        let result ← runCapaM stRef (LeanExec.carve ownerId handle access)
        match result with
        | .ok (_, _, updates) =>
          -- Register the new memcap
          let st' ← stRef.get
          -- The newly allocated cap UID is nextCapUid - 1
          let newUid := st'.execState.nextCapUid - 1
          stRef.modify (·.registerMem childName newUid)
          pure s!"Carved '{childName}' (uid={newUid}) from '{parentName}'\n{formatUpdates updates}"
        | .error e => pure s!"Error: {e}"
    -- parentName is a domain name — find the root memcap (first memcap handle)
    let some parent := st.execState.getDomain parentId
      | pure s!"Error: domain not found"
    -- For carve on a domain name, use handle 0 (root memcap)
    let handle := match parent.memCaps.head? with
      | some (h, _) => h
      | none => 0
    let rights := parseRightsString rightsStr
    let access : Access := { start := start, size := size, rights := rights }
    let result ← runCapaM stRef (LeanExec.carve parentId handle access)
    match result with
    | .ok (_, _, updates) =>
      let st' ← stRef.get
      let newUid := st'.execState.nextCapUid - 1
      stRef.modify (·.registerMem childName newUid)
      pure s!"Carved '{childName}' (uid={newUid}) from '{parentName}'\n{formatUpdates updates}"
    | .error e => pure s!"Error: {e}"

  | .alias_ parentName childName start size rightsStr => do
    let st ← stRef.get
    let some parentUid := st.lookupMem parentName
      | pure s!"Error: unknown memory '{parentName}'"
    let some parentCap := st.execState.getMemCap parentUid
      | pure s!"Error: memcap not found"
    let ownerId := parentCap.capId.domainId
    let some owner := st.execState.getDomain ownerId
      | pure s!"Error: owning domain not found"
    let some handle := findMemHandle owner parentUid
      | pure s!"Error: handle not found"
    let rights := parseRightsString rightsStr
    let access : Access := { start := start, size := size, rights := rights }
    let result ← runCapaM stRef (LeanExec.«alias» ownerId handle access)
    match result with
    | .ok (_, _) =>
      let st' ← stRef.get
      let newUid := st'.execState.nextCapUid - 1
      stRef.modify (·.registerMem childName newUid)
      pure s!"Aliased '{childName}' (uid={newUid}) from '{parentName}'"
    | .error e => pure s!"Error: {e}"

  | .send memName domName attrsStr gpa => do
    let st ← stRef.get
    -- Check if memName is a known memory region
    match st.lookupMem memName with
    | some memUid =>
      let some memCap := st.execState.getMemCap memUid
        | pure s!"Error: memcap not found"
      let senderId := memCap.capId.domainId
      let some sender := st.execState.getDomain senderId
        | pure s!"Error: sender domain not found"
      let some handle := findMemHandle sender memUid
        | pure s!"Error: handle not found"
      let some receiverId := st.lookupDomain domName
        | pure s!"Error: unknown domain '{domName}'"
      let attrs := parseAttrsString attrsStr
      let result ← runCapaM stRef (LeanExec.send senderId handle receiverId attrs gpa)
      match result with
      | .ok updates => pure s!"Sent '{memName}' to '{domName}'\n{formatUpdates updates}"
      | .error e => pure s!"Error: {e}"
    | none =>
      -- Check if it's a channel name
      match st.lookupChan memName with
      | some (ownerId, chanHandle) =>
        let some receiverId := st.lookupDomain domName
          | pure s!"Error: unknown domain '{domName}'"
        let result ← runCapaM stRef (LeanExec.sendChannel ownerId chanHandle receiverId)
        match result with
        | .ok () => pure s!"Sent channel '{memName}' to '{domName}'"
        | .error e => pure s!"Error: {e}"
      | none => pure s!"Error: unknown memory/channel '{memName}'"

  | .«seal» domName => do
    let st ← stRef.get
    let some domId := st.lookupDomain domName
      | pure s!"Error: unknown domain '{domName}'"
    -- Find parent that owns the dom capability
    let some dom := st.execState.getDomain domId
      | pure s!"Error: domain not found"
    let some parentId := dom.parentDomId
      | pure s!"Error: domain has no parent (root?)"
    let some parent := st.execState.getDomain parentId
      | pure s!"Error: parent domain not found"
    let some handle := findDomHandle parent domId
      | pure s!"Error: handle not found in parent"
    let result ← runCapaM stRef (LeanExec.«seal» parentId handle)
    match result with
    | .ok () => pure s!"Sealed domain '{domName}'"
    | .error e => pure s!"Error: {e}"

  | .revoke parentName childName => do
    let st ← stRef.get
    -- Try as domain revocation first
    match st.lookupDomain parentName, st.lookupDomain childName with
    | some parentId, some childId =>
      let some parent := st.execState.getDomain parentId
        | pure s!"Error: parent not found"
      let some handle := findDomHandle parent childId
        | pure s!"Error: '{childName}' not found in '{parentName}' domCaps"
      let result ← runCapaM stRef (LeanExec.revokeDomain parentId handle)
      match result with
      | .ok updates => pure s!"Revoked domain '{childName}'\n{formatUpdates updates}"
      | .error e => pure s!"Error: {e}"
    | _, _ =>
      -- Try as memcap revocation: parentName is a memcap, childName is a sub-region
      match st.lookupMem parentName, st.lookupMem childName with
      | some parentUid, some childUid =>
        let some parentCap := st.execState.getMemCap parentUid
          | pure s!"Error: parent memcap not found"
        let some childCap := st.execState.getMemCap childUid
          | pure s!"Error: child memcap not found"
        let ownerId := parentCap.capId.domainId
        let some owner := st.execState.getDomain ownerId
          | pure s!"Error: owner not found"
        let some handle := findMemHandle owner parentUid
          | pure s!"Error: handle not found"
        let result ← runCapaM stRef (LeanExec.revoke ownerId handle childCap.capId.subHandle)
        match result with
        | .ok updates => pure s!"Revoked memcap '{childName}'\n{formatUpdates updates}"
        | .error e => pure s!"Error: {e}"
      | _, _ => pure s!"Error: unknown parent/child '{parentName}'/'{childName}'"

  | .switchCmd domName core vpId => do
    let st ← stRef.get
    match domName, vpId with
    | none, none =>
      -- Return switch: find which domain is running on this core
      match st.execState.getCoreState core with
      | some (.runningDomain domId _) =>
        let result ← runCapaM stRef (LeanExec.switchReturn domId core)
        match result with
        | .ok sr => pure s!"Return switch: {domainName st sr.fromDomain} → {domainName st sr.toDomain}"
        | .error e => pure s!"Error: {e}"
      | _ => pure s!"Error: no domain running on core {core}"
    | some dn, some vid =>
      let some targetId := st.lookupDomain dn
        | pure s!"Error: unknown domain '{dn}'"
      -- Find the caller: who is currently running on this core
      match st.execState.getCoreState core with
      | some (.runningDomain callerId _) =>
        let some caller := st.execState.getDomain callerId
          | pure s!"Error: caller domain not found"
        -- Find the handle for the target in the caller's domCaps or chanCaps
        let handle := match findDomHandle caller targetId with
          | some h => h
          | none =>
            match caller.chanCaps.find? (fun p => p.2 == targetId) with
            | some (h, _) => h
            | none => 0
        let result ← runCapaM stRef (LeanExec.switchForward callerId handle core vid)
        match result with
        | .ok sr =>
          let vecMsg := match sr.vector with
            | some v => s!" (pending interrupt vector {v})"
            | none => ""
          pure s!"Forward switch: {domainName st sr.fromDomain} → {domainName st sr.toDomain}{vecMsg}"
        | .error e => pure s!"Error: {e}"
      | _ => pure s!"Error: no domain running on core {core}"
    | _, _ => pure "Error: switch requires <core> for return or <domain> <core> <vp_id> for forward"

  | .interrupt vector domName core => do
    let st ← stRef.get
    let some startId := st.lookupDomain domName
      | pure s!"Error: unknown domain '{domName}'"
    let result ← runCapaM stRef (LeanExec.handleInterrupt vector startId core)
    match result with
    | .ok sr => pure s!"Interrupt delivered: vector {vector} → {domainName st sr.toDomain}"
    | .error e => pure s!"Error: {e}"

  | .list => do
    let st ← stRef.get
    pure (formatList st)

  | .view domName => do
    let st ← stRef.get
    let some domId := st.lookupDomain domName
      | pure s!"Error: unknown domain '{domName}'"
    let result ← runCapaM stRef (LeanExec.computeAddressSpace domId)
    match result with
    | .ok addrSpace =>
      let st' ← stRef.get
      pure (formatView st' domId addrSpace)
    | .error e => pure s!"Error: {e}"

  | .enumeratePending domName => do
    let st ← stRef.get
    let some domId := st.lookupDomain domName
      | pure s!"Error: unknown domain '{domName}'"
    let result ← runCapaM stRef (LeanExec.enumeratePending domId)
    match result with
    | .ok (pendingMem, pendingDom) =>
      let st' ← stRef.get
      let mut out := s!"Pending capabilities for '{domName}':\n"
      if pendingMem.isEmpty && pendingDom.isEmpty then
        out := out ++ "  <none>\n"
      for pm in pendingMem do
        out := out ++ s!"  Mem pending#{pm.pendingId}: from {domainName st' pm.senderDomId} uid={pm.capNodeId} attrs={pm.attributes}\n"
      for pd in pendingDom do
        out := out ++ s!"  Dom pending#{pd.pendingId}: from {domainName st' pd.senderDomId} target={domainName st' pd.targetDomId}\n"
      pure out
    | .error e => pure s!"Error: {e}"

  | .acceptCapability domName pendingId gpa => do
    let st ← stRef.get
    let some domId := st.lookupDomain domName
      | pure s!"Error: unknown domain '{domName}'"
    let result ← runCapaM stRef (LeanExec.accept domId pendingId gpa)
    match result with
    | .ok (handle, updates) =>
      pure s!"Accepted pending#{pendingId} in '{domName}', handle=h{handle}\n{formatUpdates updates}"
    | .error e => pure s!"Error: {e}"

  | .rejectCapability domName pendingId => do
    let st ← stRef.get
    let some domId := st.lookupDomain domName
      | pure s!"Error: unknown domain '{domName}'"
    let result ← runCapaM stRef (LeanExec.reject domId pendingId)
    match result with
    | .ok () => pure s!"Rejected pending#{pendingId} in '{domName}'"
    | .error e => pure s!"Error: {e}"

  | .getChan targetName chanName => do
    let st ← stRef.get
    -- targetName is the name of a child domain. We need to find the parent that owns it.
    let some targetId := st.lookupDomain targetName
      | pure s!"Error: unknown domain '{targetName}'"
    let some targetDom := st.execState.getDomain targetId
      | pure s!"Error: target domain not found"
    let some parentId := targetDom.parentDomId
      | pure s!"Error: target has no parent"
    let some parent := st.execState.getDomain parentId
      | pure s!"Error: parent not found"
    let some domHandle := findDomHandle parent targetId
      | pure s!"Error: target not in parent's domCaps"
    let result ← runCapaM stRef (LeanExec.getChan parentId domHandle)
    match result with
    | .ok chanHandle =>
      stRef.modify (·.registerChan chanName parentId chanHandle)
      pure s!"Got channel '{chanName}' for '{targetName}' (handle=h{chanHandle})"
    | .error e => pure s!"Error: {e}"

  | .sendChannel chanName receiverName => do
    let st ← stRef.get
    match st.lookupChan chanName with
    | some (ownerId, chanHandle) =>
      let some receiverId := st.lookupDomain receiverName
        | pure s!"Error: unknown domain '{receiverName}'"
      let result ← runCapaM stRef (LeanExec.sendChannel ownerId chanHandle receiverId)
      match result with
      | .ok () => pure s!"Sent channel '{chanName}' to '{receiverName}'"
      | .error e => pure s!"Error: {e}"
    | none => pure s!"Error: unknown channel '{chanName}'"

  | .acceptChannel receiverName pendingId chanName => do
    let st ← stRef.get
    let some receiverId := st.lookupDomain receiverName
      | pure s!"Error: unknown domain '{receiverName}'"
    let result ← runCapaM stRef (LeanExec.acceptChannel receiverId pendingId)
    match result with
    | .ok chanHandle =>
      stRef.modify (·.registerChan chanName receiverId chanHandle)
      pure s!"Accepted channel pending#{pendingId} as '{chanName}' (handle=h{chanHandle})"
    | .error e => pure s!"Error: {e}"

  | .rejectChannel receiverName pendingId => do
    let st ← stRef.get
    let some receiverId := st.lookupDomain receiverName
      | pure s!"Error: unknown domain '{receiverName}'"
    let result ← runCapaM stRef (LeanExec.rejectChannel receiverId pendingId)
    match result with
    | .ok () => pure s!"Rejected channel pending#{pendingId} in '{receiverName}'"
    | .error e => pure s!"Error: {e}"

  | .registerComm memName childDomName vpId => do
    let st ← stRef.get
    let some memUid := st.lookupMem memName
      | pure s!"Error: unknown memory '{memName}'"
    let some memCap := st.execState.getMemCap memUid
      | pure s!"Error: memcap not found"
    let callerId := memCap.capId.domainId
    let some caller := st.execState.getDomain callerId
      | pure s!"Error: caller domain not found"
    let some commHandle := findMemHandle caller memUid
      | pure s!"Error: handle not found"
    let some childId := st.lookupDomain childDomName
      | pure s!"Error: unknown domain '{childDomName}'"
    let result ← runCapaM stRef (LeanExec.registerComm callerId commHandle childId vpId)
    match result with
    | .ok updates => pure s!"Registered COMM '{memName}' for '{childDomName}' vp={vpId}\n{formatUpdates updates}"
    | .error e => pure s!"Error: {e}"

  | .setPolicy parentName childName field value => do
    let st ← stRef.get
    let some parentId := st.lookupDomain parentName
      | pure s!"Error: unknown domain '{parentName}'"
    let some childId := st.lookupDomain childName
      | pure s!"Error: unknown domain '{childName}'"
    let some parent := st.execState.getDomain parentId
      | pure s!"Error: parent not found"
    let some handle := findDomHandle parent childId
      | pure s!"Error: '{childName}' not in '{parentName}' domCaps"
    let result ← runCapaM stRef (LeanExec.setPolicy parentId handle field value)
    match result with
    | .ok () => pure s!"Set policy {field}=0x{toHex value} on '{childName}'"
    | .error e => pure s!"Error: {e}"

  | .getPolicy parentName childName field => do
    let st ← stRef.get
    let some parentId := st.lookupDomain parentName
      | pure s!"Error: unknown domain '{parentName}'"
    let some childId := st.lookupDomain childName
      | pure s!"Error: unknown domain '{childName}'"
    let some parent := st.execState.getDomain parentId
      | pure s!"Error: parent not found"
    let some handle := findDomHandle parent childId
      | pure s!"Error: '{childName}' not in '{parentName}' domCaps"
    let result ← runCapaM stRef (LeanExec.getPolicy parentId handle field)
    match result with
    | .ok value => pure s!"Policy {field} for '{childName}': 0x{toHex value} ({value})"
    | .error e => pure s!"Error: {e}"

  | .setRegister parentName childName vpId regId value => do
    let st ← stRef.get
    let some parentId := st.lookupDomain parentName
      | pure s!"Error: unknown domain '{parentName}'"
    let some childId := st.lookupDomain childName
      | pure s!"Error: unknown domain '{childName}'"
    let some parent := st.execState.getDomain parentId
      | pure s!"Error: parent not found"
    let some handle := findDomHandle parent childId
      | pure s!"Error: '{childName}' not in '{parentName}' domCaps"
    let result ← runCapaM stRef (LeanExec.setRegister parentId handle vpId regId value)
    match result with
    | .ok () => pure s!"Set register vp={vpId} reg={regId} = 0x{toHex value} on '{childName}'"
    | .error e => pure s!"Error: {e}"

  | .getRegister parentName childName vpId regId => do
    let st ← stRef.get
    let some parentId := st.lookupDomain parentName
      | pure s!"Error: unknown domain '{parentName}'"
    let some childId := st.lookupDomain childName
      | pure s!"Error: unknown domain '{childName}'"
    let some parent := st.execState.getDomain parentId
      | pure s!"Error: parent not found"
    let some handle := findDomHandle parent childId
      | pure s!"Error: '{childName}' not in '{parentName}' domCaps"
    let result ← runCapaM stRef (LeanExec.getRegister parentId handle vpId regId)
    match result with
    | .ok value => pure s!"Register vp={vpId} reg={regId} for '{childName}': 0x{toHex value} ({value})"
    | .error e => pure s!"Error: {e}"

  | .attest domName => do
    let st ← stRef.get
    let some domId := st.lookupDomain domName
      | pure s!"Error: unknown domain '{domName}'"
    -- Self-attestation
    let result ← runCapaM stRef (LeanExec.attestSelf domId)
    match result with
    | .ok report => pure report
    | .error e => pure s!"Error: {e}"

  | .setInterruptPolicy domName vector visibility => do
    let st ← stRef.get
    let some domId := st.lookupDomain domName
      | pure s!"Error: unknown domain '{domName}'"
    let some dom := st.execState.getDomain domId
      | pure s!"Error: domain not found"
    let some parentId := dom.parentDomId
      | pure s!"Error: domain has no parent"
    let some parent := st.execState.getDomain parentId
      | pure s!"Error: parent not found"
    let some handle := findDomHandle parent domId
      | pure s!"Error: domain not in parent's domCaps"
    let result ← runCapaM stRef (LeanExec.setInterruptPolicy parentId handle vector visibility)
    match result with
    | .ok () =>
      let pol := if visibility == 1 then "deliver"
        else if visibility == 2 then "deliverAndClear"
        else "deny"
      pure s!"Set interrupt policy vector={vector} → {pol} on '{domName}'"
    | .error e => pure s!"Error: {e}"

  | .addVp parentName childName commMemName vpId => do
    let st ← stRef.get
    let some parentId := st.lookupDomain parentName
      | pure s!"Error: unknown domain '{parentName}'"
    let some childId := st.lookupDomain childName
      | pure s!"Error: unknown domain '{childName}'"
    let some parent := st.execState.getDomain parentId
      | pure s!"Error: parent not found"
    let some domHandle := findDomHandle parent childId
      | pure s!"Error: '{childName}' not in '{parentName}' domCaps"
    let some commUid := st.lookupMem commMemName
      | pure s!"Error: unknown memory '{commMemName}'"
    let some commHandle := findMemHandle parent commUid
      | pure s!"Error: COMM memory handle not found in '{parentName}'"
    let result ← runCapaM stRef (LeanExec.addVp parentId domHandle commHandle vpId)
    match result with
    | .ok updates => pure s!"Added VP {vpId} to '{childName}' with COMM '{commMemName}'\n{formatUpdates updates}"
    | .error e => pure s!"Error: {e}"

  | .help => pure helpText

  | .reset numCores => do
    stRef.set { CliState.empty with execState := ExecState.empty numCores }
    pure s!"State reset ({numCores} cores)"

where
  helpText : String :=
    "Commands:\n" ++
    "  init <name> <size>                         — Initialize root domain + memory\n" ++
    "  create-domain <parent> <name> <cores> <api> — Create child domain\n" ++
    "  carve <parent> <name> <start> <size> <rights> — Carve memory region\n" ++
    "  alias <parent> <name> <start> <size> <rights> — Alias memory region\n" ++
    "  send <mem> <domain> [attrs] [at <gpa>]      — Send memory to domain\n" ++
    "  seal <domain>                                — Seal domain\n" ++
    "  revoke <parent> <child>                      — Revoke domain or memcap\n" ++
    "  switch <core>                                — Return switch\n" ++
    "  switch <domain> <core> <vp_id>               — Forward switch\n" ++
    "  interrupt <vector> <domain> <core>            — Deliver interrupt\n" ++
    "  list                                         — Show full state\n" ++
    "  view <domain>                                — Show domain address space\n" ++
    "  enumerate-pending <domain>                   — List pending transfers\n" ++
    "  accept-capability <domain> <id> [at <gpa>]   — Accept pending memcap\n" ++
    "  reject-capability <domain> <id>              — Reject pending memcap\n" ++
    "  get-chan <target> <chan_name>                 — Get channel capability\n" ++
    "  send-channel <chan> <receiver>               — Send channel to domain\n" ++
    "  accept-channel <receiver> <id> <chan_name>   — Accept pending channel\n" ++
    "  reject-channel <receiver> <id>               — Reject pending channel\n" ++
    "  register-comm <mem> <child> <vp_id>          — Register COMM page\n" ++
    "  set-policy <parent> <child> <field> <value>  — Set policy field\n" ++
    "  get-policy <parent> <child> <field>          — Get policy field\n" ++
    "  set-register <parent> <child> <vp> <reg> <val> — Set VP register\n" ++
    "  get-register <parent> <child> <vp> <reg>     — Get VP register\n" ++
    "  attest <domain>                              — Attestation hash\n" ++
    "  set-interrupt-policy <domain> <vec> <vis>    — Set interrupt policy\n" ++
    "  add-vp <parent> <child> <comm_mem> <vp_id>  — Add VP with COMM\n" ++
    "  load <filename>                             — Load commands from file\n" ++
    "  reset [numCores]                            — Reset state\n" ++
    "  help                                        — Show this help\n" ++
    "  quit / exit                                 — Exit REPL\n"

end LeanExec
