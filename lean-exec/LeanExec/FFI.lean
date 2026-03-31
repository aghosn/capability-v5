/-
  LeanExec.FFI — C-callable exported functions for the Lean capability engine.

  Architecture:
    - Global IO.Ref holds the ExecState (single-threaded, no locking needed)
    - Each @[export] function is `IO UInt32` returning an error code (0 = success)
    - Results written to global "slot" refs, read by separate getters
    - HwUpdate buffer stored globally, accessed via count + field getters
    - Query results serialized to JSON strings in gResultStr
    
  The Rust LeanBackend calls these via C FFI (extern "C").
  All domain/memcap IDs are UInt64 (Nat internally).
-/
import LeanExec.Operations.Memory
import LeanExec.Operations.Domain
import LeanExec.Operations.Channel
import LeanExec.Operations.Switch
import LeanExec.Operations.Policy
import LeanExec.Operations.Query

namespace LeanExec.FFI

open ThemisCapa LeanExec

-- ════════════════════════════════════════════════════════════════════
-- § Global state
-- ════════════════════════════════════════════════════════════════════

instance : Inhabited ExecState := ⟨ExecState.empty 0⟩

initialize gState    : IO.Ref ExecState ← IO.mkRef (ExecState.empty 4)
initialize gNumCores : IO.Ref Nat       ← IO.mkRef 4

-- Result slots
initialize gResult1   : IO.Ref UInt64 ← IO.mkRef 0
initialize gResult2   : IO.Ref UInt64 ← IO.mkRef 0
initialize gResultStr : IO.Ref String ← IO.mkRef ""
initialize gErrorMsg  : IO.Ref String ← IO.mkRef ""

-- Update buffer
initialize gUpdates : IO.Ref (Array HwUpdate) ← IO.mkRef #[]

-- Channel UID mapping: synthetic channel UID → (ownerDomId, localHandle)
initialize gChanMap    : IO.Ref (List (UInt64 × (DomainId × LocalHandle))) ← IO.mkRef []
initialize gNextChanId : IO.Ref UInt64 ← IO.mkRef 0

-- ════════════════════════════════════════════════════════════════════
-- § Error mapping
-- ════════════════════════════════════════════════════════════════════

def errorToCode : CapaError → UInt32
  | .domainRevoked         => 1
  | .invalidAccess         => 2
  | .permissionDenied      => 3
  | .notFound              => 4
  | .domainSealed          => 5
  | .domainNotSealed       => 6
  | .parentRevoked         => 7
  | .regionOverlap         => 8
  | .monotonicityViolation => 9
  | .apiNotAllowed         => 10
  | .invalidOperation _    => 11

def returnError (e : CapaError) : IO UInt32 := do
  gErrorMsg.set (toString e)
  pure (errorToCode e)

-- ════════════════════════════════════════════════════════════════════
-- § Handle resolution helpers
-- ════════════════════════════════════════════════════════════════════

def resolveMemHandle (st : ExecState) (domId : DomainId) (uid : MemCapUid)
    : Option LocalHandle :=
  match st.getDomain domId with
  | some dom => (dom.memCaps.find? (fun p => p.2 == uid)).map Prod.fst
  | none => none

def resolveDomHandle (st : ExecState) (parentId childId : DomainId)
    : Option LocalHandle :=
  match st.getDomain parentId with
  | some dom => (dom.domCaps.find? (fun p => p.2 == childId)).map Prod.fst
  | none => none

def findMemOwner (st : ExecState) (uid : MemCapUid) : Option DomainId :=
  match st.getMemCap uid with
  | some cap => some cap.capId.domainId
  | none => none

def findMemUidByHandle (st : ExecState) (domId : DomainId) (handle : LocalHandle)
    : Option MemCapUid :=
  match st.getDomain domId with
  | some dom => dom.lookupMemUid handle
  | none => none

-- ════════════════════════════════════════════════════════════════════
-- § CapaM execution helper
-- ════════════════════════════════════════════════════════════════════

/-- Run a CapaM operation. On success, update global state. On error, leave state unchanged. -/
def runOp (m : CapaM α) : IO (Except CapaError α) := do
  let st ← gState.get
  let (result, newSt) := CapaM.run m st
  match result with
  | .ok val =>
    gState.set newSt
    pure (.ok val)
  | .error e =>
    pure (.error e)

def storeUpdates (updates : UpdateBatch) : IO Unit :=
  gUpdates.set updates.toArray

-- ════════════════════════════════════════════════════════════════════
-- § Bit encoding helpers
-- ════════════════════════════════════════════════════════════════════

def rightsFromBits (bits : Nat) : Rights :=
  { read    := (bits &&& 1) != 0
    write   := (bits &&& 2) != 0
    execute := (bits &&& 4) != 0 }

def rightsToBits (r : Rights) : Nat :=
  (if r.read then 1 else 0) +
  (if r.write then 2 else 0) +
  (if r.execute then 4 else 0)

def attrsFromBits (bits : Nat) : Attributes :=
  { hash  := (bits &&& 1) != 0
    clean := (bits &&& 2) != 0
    vital := (bits &&& 4) != 0
    «meta»  := (bits &&& 8) != 0
    comm  := (bits &&& 16) != 0 }

def coreMaskToList (mask : Nat) : List Nat :=
  (List.range 64).filter mask.testBit

def coreListToMask (cores : List Nat) : Nat :=
  cores.foldl (fun acc c => acc + (1 <<< c)) 0

def apiFromBits (bits : Nat) : MonitorAPI :=
  { canCreate           := (bits &&& 1) != 0
    canSet              := (bits &&& 2) != 0
    canGet              := (bits &&& 4) != 0
    canSend             := (bits &&& 8) != 0
    canSeal             := (bits &&& 16) != 0
    canAttest           := (bits &&& 32) != 0
    canEnumerate        := (bits &&& 64) != 0
    canSwitch           := (bits &&& 128) != 0
    canAlias            := (bits &&& 256) != 0
    canCarve            := (bits &&& 512) != 0
    canRevoke           := (bits &&& 1024) != 0
    canGetChan          := (bits &&& 2048) != 0
    canReceiveAfterSeal := (bits &&& 4096) != 0 }

def apiToBits (a : MonitorAPI) : Nat :=
  (if a.canCreate then 1 else 0) +
  (if a.canSet then 2 else 0) +
  (if a.canGet then 4 else 0) +
  (if a.canSend then 8 else 0) +
  (if a.canSeal then 16 else 0) +
  (if a.canAttest then 32 else 0) +
  (if a.canEnumerate then 64 else 0) +
  (if a.canSwitch then 128 else 0) +
  (if a.canAlias then 256 else 0) +
  (if a.canCarve then 512 else 0) +
  (if a.canRevoke then 1024 else 0) +
  (if a.canGetChan then 2048 else 0) +
  (if a.canReceiveAfterSeal then 4096 else 0)

-- ════════════════════════════════════════════════════════════════════
-- § JSON helpers (minimal serializer for query results)
-- ════════════════════════════════════════════════════════════════════

private def toHex (n : Nat) : String :=
  if n == 0 then "0" else String.ofList (Nat.toDigits 16 n)

private def jsonNum (n : Nat) : String := toString n
private def jsonStr (s : String) : String :=
  "\"" ++ (s.replace "\\" "\\\\" |>.replace "\"" "\\\"" |>.replace "\n" "\\n") ++ "\""
private def jsonBool (b : Bool) : String := if b then "true" else "false"
private def jsonNull : String := "null"
private def jsonArr (items : List String) : String :=
  "[" ++ ",".intercalate items ++ "]"
private def jsonObj (fields : List (String × String)) : String :=
  "{" ++ ",".intercalate (fields.map fun (k, v) => jsonStr k ++ ":" ++ v) ++ "}"
private def jsonOptNum (v : Option Nat) : String :=
  match v with | some n => jsonNum n | none => jsonNull

-- ════════════════════════════════════════════════════════════════════
-- § Lifecycle exports
-- ════════════════════════════════════════════════════════════════════

@[export lean_exec_init]
def ffiInit (memSize numCores : UInt64) : IO UInt32 := do
  gNumCores.set numCores.toNat
  gChanMap.set []
  gNextChanId.set 0
  let result ← runOp (LeanExec.init memSize.toNat numCores.toNat)
  match result with
  | .ok (domId, memUid) =>
    gResult1.set domId.toUInt64
    gResult2.set memUid.toUInt64
    storeUpdates []
    pure 0
  | .error e => returnError e

@[export lean_exec_reset]
def ffiReset (numCores : UInt64) : IO UInt32 := do
  gState.set (ExecState.empty numCores.toNat)
  gNumCores.set numCores.toNat
  gChanMap.set []
  gNextChanId.set 0
  gUpdates.set #[]
  pure 0

-- ════════════════════════════════════════════════════════════════════
-- § Memory operation exports
-- ════════════════════════════════════════════════════════════════════

@[export lean_exec_carve]
def ffiCarve (owner parentUid start size rights : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some parentHandle := resolveMemHandle st owner.toNat parentUid.toNat
    | returnError .notFound
  let access : Access := {
    start := start.toNat, size := size.toNat,
    rights := rightsFromBits rights.toNat }
  let result ← runOp (LeanExec.carve owner.toNat parentHandle access)
  match result with
  | .ok (childHandle, _, updates) =>
    let st' ← gState.get
    let some childUid := findMemUidByHandle st' owner.toNat childHandle
      | returnError (.invalidOperation "child UID not found after carve")
    gResult1.set childUid.toUInt64
    storeUpdates updates
    pure 0
  | .error e => returnError e

@[export lean_exec_alias]
def ffiAlias (owner parentUid start size rights : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some parentHandle := resolveMemHandle st owner.toNat parentUid.toNat
    | returnError .notFound
  let access : Access := {
    start := start.toNat, size := size.toNat,
    rights := rightsFromBits rights.toNat }
  let result ← runOp (LeanExec.«alias» owner.toNat parentHandle access)
  match result with
  | .ok (childHandle, _) =>
    let st' ← gState.get
    let some childUid := findMemUidByHandle st' owner.toNat childHandle
      | returnError (.invalidOperation "child UID not found after alias")
    gResult1.set childUid.toUInt64
    storeUpdates []
    pure 0
  | .error e => returnError e

@[export lean_exec_send]
def ffiSend (memUid receiverId attrs gpaVal hasGpa : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some callerId := findMemOwner st memUid.toNat
    | returnError .notFound
  let some capHandle := resolveMemHandle st callerId memUid.toNat
    | returnError .notFound
  let gpaHint := if hasGpa.toNat != 0 then some gpaVal.toNat else none
  let leanAttrs := attrsFromBits attrs.toNat
  let result ← runOp (LeanExec.send callerId capHandle receiverId.toNat leanAttrs gpaHint)
  match result with
  | .ok updates =>
    storeUpdates updates
    pure 0
  | .error e => returnError e

@[export lean_exec_accept]
def ffiAccept (domId pendingId gpaVal hasGpa : UInt64) : IO UInt32 := do
  let gpaOverride := if hasGpa.toNat != 0 then some gpaVal.toNat else none
  let result ← runOp (LeanExec.accept domId.toNat pendingId.toNat gpaOverride)
  match result with
  | .ok (recvHandle, updates) =>
    let st' ← gState.get
    let some memUid := findMemUidByHandle st' domId.toNat recvHandle
      | returnError (.invalidOperation "mem UID not found after accept")
    gResult1.set memUid.toUInt64
    storeUpdates updates
    pure 0
  | .error e => returnError e

@[export lean_exec_reject]
def ffiReject (domId pendingId : UInt64) : IO UInt32 := do
  let result ← runOp (LeanExec.reject domId.toNat pendingId.toNat)
  match result with
  | .ok () => storeUpdates []; pure 0
  | .error e => returnError e

@[export lean_exec_revoke_mem]
def ffiRevokeMem (owner parentUid childUid : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some parentHandle := resolveMemHandle st owner.toNat parentUid.toNat
    | returnError .notFound
  let some childCap := st.getMemCap childUid.toNat
    | returnError .notFound
  let childSub := childCap.capId.subHandle
  let result ← runOp (LeanExec.revoke owner.toNat parentHandle childSub)
  match result with
  | .ok updates => storeUpdates updates; pure 0
  | .error e => returnError e

-- ════════════════════════════════════════════════════════════════════
-- § Domain operation exports
-- ════════════════════════════════════════════════════════════════════

@[export lean_exec_create_domain]
def ffiCreateDomain (parentId cores api : UInt64) : IO UInt32 := do
  let policy : DomainPolicy := {
    cores := coreMaskToList cores.toNat
    api := apiFromBits api.toNat
    interrupts := { defaultPolicy := .deliver, perVector := [] }
    numVps := 0 }
  let result ← runOp (LeanExec.create parentId.toNat policy)
  match result with
  | .ok (_, newId, updates) =>
    gResult1.set newId.toUInt64
    storeUpdates updates
    pure 0
  | .error e => returnError e

@[export lean_exec_seal]
def ffiSeal (owner childId : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some childHandle := resolveDomHandle st owner.toNat childId.toNat
    | returnError .notFound
  let result ← runOp (LeanExec.«seal» owner.toNat childHandle)
  match result with
  | .ok () => storeUpdates []; pure 0
  | .error e => returnError e

@[export lean_exec_revoke_domain]
def ffiRevokeDomain (parentId childId : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some childHandle := resolveDomHandle st parentId.toNat childId.toNat
    | returnError .notFound
  let result ← runOp (LeanExec.revokeDomain parentId.toNat childHandle)
  match result with
  | .ok updates => storeUpdates updates; pure 0
  | .error e => returnError e

-- ════════════════════════════════════════════════════════════════════
-- § Channel operation exports
-- ════════════════════════════════════════════════════════════════════

private def allocChanId : IO UInt64 := do
  let id ← gNextChanId.get
  gNextChanId.set (id + 1)
  pure id

@[export lean_exec_get_chan]
def ffiGetChan (callerId targetId : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some targetHandle := resolveDomHandle st callerId.toNat targetId.toNat
    | returnError .notFound
  let result ← runOp (LeanExec.getChan callerId.toNat targetHandle)
  match result with
  | .ok chanHandle =>
    let chanId ← allocChanId
    gChanMap.modify (· ++ [(chanId, (callerId.toNat, chanHandle))])
    gResult1.set chanId
    storeUpdates []
    pure 0
  | .error e => returnError e

@[export lean_exec_send_channel]
def ffiSendChannel (callerId chanId receiverId : UInt64) : IO UInt32 := do
  let chanMap ← gChanMap.get
  let some (_, (_, chanHandle)) := chanMap.find? (fun p => p.1 == chanId)
    | returnError .notFound
  let result ← runOp (LeanExec.sendChannel callerId.toNat chanHandle receiverId.toNat)
  match result with
  | .ok () => storeUpdates []; pure 0
  | .error e => returnError e

@[export lean_exec_accept_channel]
def ffiAcceptChannel (receiverId pendingId : UInt64) : IO UInt32 := do
  let result ← runOp (LeanExec.acceptChannel receiverId.toNat pendingId.toNat)
  match result with
  | .ok chanHandle =>
    let chanId ← allocChanId
    gChanMap.modify (· ++ [(chanId, (receiverId.toNat, chanHandle))])
    gResult1.set chanId
    storeUpdates []
    pure 0
  | .error e => returnError e

@[export lean_exec_reject_channel]
def ffiRejectChannel (receiverId pendingId : UInt64) : IO UInt32 := do
  let result ← runOp (LeanExec.rejectChannel receiverId.toNat pendingId.toNat)
  match result with
  | .ok () => storeUpdates []; pure 0
  | .error e => returnError e

-- ════════════════════════════════════════════════════════════════════
-- § VP & Switch exports
-- ════════════════════════════════════════════════════════════════════

@[export lean_exec_add_vp]
def ffiAddVp (parentId childId commUid vpId : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some childHandle := resolveDomHandle st parentId.toNat childId.toNat
    | returnError .notFound
  let some commHandle := resolveMemHandle st parentId.toNat commUid.toNat
    | returnError .notFound
  let result ← runOp (LeanExec.addVp parentId.toNat childHandle commHandle vpId.toNat)
  match result with
  | .ok updates => storeUpdates updates; pure 0
  | .error e => returnError e

@[export lean_exec_register_comm]
def ffiRegisterComm (ownerId commUid childId vpId : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some commHandle := resolveMemHandle st ownerId.toNat commUid.toNat
    | returnError .notFound
  let result ← runOp (LeanExec.registerComm ownerId.toNat commHandle childId.toNat vpId.toNat)
  match result with
  | .ok updates => storeUpdates updates; pure 0
  | .error e => returnError e

private def storeSwitchResult (sr : SwitchResult) : IO Unit := do
  gResult1.set sr.fromDomain.toUInt64
  gResult2.set sr.toDomain.toUInt64
  let vecStr := match sr.vector with | some v => toString v | none => ""
  gResultStr.set s!"{sr.isReturn}|{vecStr}"

@[export lean_exec_switch_forward]
def ffiSwitchForward (targetDomId coreId vpId : UInt64) : IO UInt32 := do
  let st ← gState.get
  -- Find current domain running on this core
  let some (.runningDomain callerId _) := st.getCoreState coreId.toNat
    | returnError (.invalidOperation "no domain on core")
  -- Resolve target: try domCaps first, then chanCaps
  let targetHandle := match resolveDomHandle st callerId targetDomId.toNat with
    | some h => h
    | none => match st.getDomain callerId with
      | some dom => match (dom.chanCaps.find? (fun p => p.2 == targetDomId.toNat)).map Prod.fst with
        | some h => h
        | none => 0  -- will fail in operation
      | none => 0
  let result ← runOp (LeanExec.switchForward callerId targetHandle coreId.toNat vpId.toNat)
  match result with
  | .ok sr => storeSwitchResult sr; storeUpdates []; pure 0
  | .error e => returnError e

@[export lean_exec_switch_return]
def ffiSwitchReturn (coreId : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some (.runningDomain calleeDomId _) := st.getCoreState coreId.toNat
    | returnError (.invalidOperation "no domain on core")
  let result ← runOp (LeanExec.switchReturn calleeDomId coreId.toNat)
  match result with
  | .ok sr => storeSwitchResult sr; storeUpdates []; pure 0
  | .error e => returnError e

@[export lean_exec_deliver_interrupt]
def ffiDeliverInterrupt (vector domainId coreId : UInt64) : IO UInt32 := do
  let result ← runOp (LeanExec.deliverInterrupt vector.toNat domainId.toNat coreId.toNat)
  match result with
  | .ok _ => storeUpdates []; pure 0
  | .error e => returnError e

-- ════════════════════════════════════════════════════════════════════
-- § Policy & Register exports
-- ════════════════════════════════════════════════════════════════════

-- Field codes: 0=cores, 1=api-monitor, 2=default-visibility, 3=num-vps
private def fieldCodeToStr : Nat → String
  | 0 => "cores"
  | 1 => "api-monitor"
  | 2 => "default-visibility"
  | 3 => "num-vps"
  | _ => "unknown"

@[export lean_exec_set_policy]
def ffiSetPolicy (parentId childId fieldCode value : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some childHandle := resolveDomHandle st parentId.toNat childId.toNat
    | returnError .notFound
  let result ← runOp (LeanExec.setPolicy parentId.toNat childHandle
    (fieldCodeToStr fieldCode.toNat) value.toNat)
  match result with
  | .ok () => storeUpdates []; pure 0
  | .error e => returnError e

@[export lean_exec_get_policy]
def ffiGetPolicy (parentId childId fieldCode : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some childHandle := resolveDomHandle st parentId.toNat childId.toNat
    | returnError .notFound
  let result ← runOp (LeanExec.getPolicy parentId.toNat childHandle
    (fieldCodeToStr fieldCode.toNat))
  match result with
  | .ok val => gResult1.set val.toUInt64; storeUpdates []; pure 0
  | .error e => returnError e

@[export lean_exec_set_register]
def ffiSetRegister (parentId childId vpId regId value : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some childHandle := resolveDomHandle st parentId.toNat childId.toNat
    | returnError .notFound
  let result ← runOp (LeanExec.setRegister parentId.toNat childHandle
    vpId.toNat regId.toNat value.toNat)
  match result with
  | .ok () => storeUpdates []; pure 0
  | .error e => returnError e

@[export lean_exec_get_register]
def ffiGetRegister (parentId childId vpId regId : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some childHandle := resolveDomHandle st parentId.toNat childId.toNat
    | returnError .notFound
  let result ← runOp (LeanExec.getRegister parentId.toNat childHandle
    vpId.toNat regId.toNat)
  match result with
  | .ok val => gResult1.set val.toUInt64; storeUpdates []; pure 0
  | .error e => returnError e

@[export lean_exec_set_interrupt_policy]
def ffiSetInterruptPolicy (ownerId childId vector visibility : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some childHandle := resolveDomHandle st ownerId.toNat childId.toNat
    | returnError .notFound
  let result ← runOp (LeanExec.setInterruptPolicy ownerId.toNat childHandle
    vector.toNat visibility.toNat)
  match result with
  | .ok () => storeUpdates []; pure 0
  | .error e => returnError e

-- ════════════════════════════════════════════════════════════════════
-- § Result & Update access exports
-- ════════════════════════════════════════════════════════════════════

@[export lean_exec_get_result1]
def ffiGetResult1 : IO UInt64 := gResult1.get

@[export lean_exec_get_result2]
def ffiGetResult2 : IO UInt64 := gResult2.get

@[export lean_exec_get_result_str]
def ffiGetResultStr : IO String := gResultStr.get

@[export lean_exec_get_error_msg]
def ffiGetErrorMsg : IO String := gErrorMsg.get

@[export lean_exec_update_count]
def ffiUpdateCount : IO UInt64 := do
  let updates ← gUpdates.get
  pure updates.size.toUInt64

-- Update field access: each update has 6 fields accessed by index
-- kind(0), domain_id(1), gpa(2), hpa(3), size(4), rights_bits(5)
-- Kind: 0=MapMemory, 1=UnmapMemory, 2=ZeroMemory, 3=CreateDomain,
--       4=RevokeDomain, 5=CommRegion, 6=UncommRegion

private def hwUpdateField (u : HwUpdate) (field : Nat) : UInt64 :=
  match u, field with
  | .mapMemory _ _ _ _ _, 0 => 0
  | .mapMemory d _ _ _ _, 1 => d.toUInt64
  | .mapMemory _ gpa _ _ _, 2 => gpa.toUInt64
  | .mapMemory _ _ hpa _ _, 3 => hpa.toUInt64
  | .mapMemory _ _ _ sz _, 4 => sz.toUInt64
  | .mapMemory _ _ _ _ r, 5 => (rightsToBits r).toUInt64
  | .unmapMemory _ _ _, 0 => 1
  | .unmapMemory d _ _, 1 => d.toUInt64
  | .unmapMemory _ gpa _, 2 => gpa.toUInt64
  | .unmapMemory _ _ sz, 4 => sz.toUInt64
  | .zeroMemory _ _, 0 => 2
  | .zeroMemory hpa _, 3 => hpa.toUInt64
  | .zeroMemory _ sz, 4 => sz.toUInt64
  | .createDomain _ _, 0 => 3
  | .createDomain d _, 1 => d.toUInt64
  | .createDomain _ p, 2 => (p.getD 0).toUInt64
  | .revokeDomain _ _, 0 => 4
  | .revokeDomain d _, 1 => d.toUInt64
  | .revokeDomain _ f, 2 => f.toUInt64
  | .commRegion _ _ _ _ _, 0 => 5
  | .commRegion c _ _ _ _, 1 => c.toUInt64
  | .commRegion _ t _ _ _, 2 => t.toUInt64
  | .commRegion _ _ v _ _, 3 => v.toUInt64
  | .commRegion _ _ _ h _, 4 => h.toUInt64
  | .commRegion _ _ _ _ s, 5 => s.toUInt64
  | .uncommRegion _ _ _ _ _, 0 => 6
  | .uncommRegion o _ _ _ _, 1 => o.toUInt64
  | .uncommRegion _ t _ _ _, 2 => t.toUInt64
  | .uncommRegion _ _ v _ _, 3 => v.toUInt64
  | .uncommRegion _ _ _ h _, 4 => h.toUInt64
  | .uncommRegion _ _ _ _ s, 5 => s.toUInt64
  | _, _ => 0

@[export lean_exec_update_field]
def ffiUpdateField (idx fieldIdx : UInt64) : IO UInt64 := do
  let updates ← gUpdates.get
  if h : idx.toNat < updates.size then
    pure (hwUpdateField updates[idx.toNat] fieldIdx.toNat)
  else pure 0

-- ════════════════════════════════════════════════════════════════════
-- § Query exports (return JSON strings in gResultStr)
-- ════════════════════════════════════════════════════════════════════

private def vpStateToJson (vp : VProcessor) : String :=
  jsonObj [
    ("vp_id", jsonNum vp.id),
    ("state", jsonStr (toString vp.runState)) ]

private def domainInfoToJson (dom : ExecDomain) : String :=
  jsonObj [
    ("id", jsonNum dom.domainId),
    ("status", jsonStr (toString dom.status)),
    ("is_channel", jsonBool false),
    ("channel_target", jsonNull),
    ("cores_bitmap", jsonNum (coreListToMask dom.policy.cores)),
    ("api_flags", jsonStr (toString dom.policy.api)),
    ("num_vps", jsonNum dom.vps.size),
    ("vp_states", jsonArr (dom.vps.toList.map vpStateToJson)) ]

@[export lean_exec_list_domains]
def ffiListDomains : IO UInt32 := do
  let st ← gState.get
  let domains := st.domains.map fun (_, dom) => domainInfoToJson dom
  gResultStr.set (jsonArr domains)
  pure 0

private partial def memCapToJson (st : ExecState) (uid : MemCapUid)
    (localHandle : Nat) : String :=
  match st.getMemCap uid with
  | some cap =>
    let children := cap.childUids.toList.map fun childUid =>
      memCapToJson st childUid 0
    jsonObj [
      ("uid", jsonNum uid),
      ("local_handle", jsonNum localHandle),
      ("start", jsonNum cap.region.access.start),
      ("end", jsonNum (cap.region.access.start + cap.region.access.size)),
      ("rights", jsonStr (toString cap.region.access.rights)),
      ("kind", jsonStr (toString cap.region.kind)),
      ("status", jsonStr (toString cap.region.status)),
      ("attributes", jsonStr (toString cap.attributes)),
      ("owner_id", jsonNum cap.capId.domainId),
      ("num_children", jsonNum cap.childUids.size),
      ("children", jsonArr children) ]
  | none => jsonNull

@[export lean_exec_get_domain_mem_caps]
def ffiGetDomainMemCaps (domId : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some dom := st.getDomain domId.toNat
    | returnError .notFound
  let caps := dom.memCaps.map fun (handle, uid) =>
    memCapToJson st uid handle
  gResultStr.set (jsonArr caps)
  pure 0

@[export lean_exec_get_domain_dom_caps]
def ffiGetDomainDomCaps (domId : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some dom := st.getDomain domId.toNat
    | returnError .notFound
  let domCaps := dom.domCaps.map fun (handle, childId) =>
    jsonObj [
      ("local_handle", jsonNum handle),
      ("domain_id", jsonNum childId),
      ("is_channel", jsonBool false) ]
  let chanCaps := dom.chanCaps.map fun (handle, targetId) =>
    jsonObj [
      ("local_handle", jsonNum handle),
      ("domain_id", jsonNum targetId),
      ("is_channel", jsonBool true) ]
  gResultStr.set (jsonArr (domCaps ++ chanCaps))
  pure 0

@[export lean_exec_get_pending_caps]
def ffiGetPendingCaps (domId : UInt64) : IO UInt32 := do
  let st ← gState.get
  let some dom := st.getDomain domId.toNat
    | returnError .notFound
  let memPending := dom.pendingMem.map fun pm =>
    let (s, e, r) := match st.getMemCap pm.memCapUid with
      | some cap => (cap.region.access.start,
          cap.region.access.start + cap.region.access.size,
          toString cap.region.access.rights)
      | none => (0, 0, "???")
    jsonObj [
      ("pending_id", jsonNum pm.pendingId),
      ("is_domain", jsonBool false),
      ("sender_id", jsonNum pm.senderDomId),
      ("start", jsonNum s),
      ("end", jsonNum e),
      ("rights", jsonStr r) ]
  let domPending := dom.pendingDom.map fun pd =>
    jsonObj [
      ("pending_id", jsonNum pd.pendingId),
      ("is_domain", jsonBool true),
      ("sender_id", jsonNum pd.senderDomId),
      ("start", jsonNum 0),
      ("end", jsonNum 0),
      ("rights", jsonStr "") ]
  gResultStr.set (jsonArr (memPending ++ domPending))
  pure 0

@[export lean_exec_get_address_space]
def ffiGetAddressSpace (domId : UInt64) : IO UInt32 := do
  let result ← runOp (LeanExec.computeAddressSpace domId.toNat)
  match result with
  | .ok regions =>
    let json := regions.map fun (start, size, rights) =>
      jsonObj [
        ("gpa", jsonNum start),
        ("size", jsonNum size),
        ("rights", jsonStr (toString rights)),
        ("hpa", jsonNum start),
        ("is_identity_mapped", jsonBool true) ]
    gResultStr.set (jsonArr json)
    pure 0
  | .error e => returnError e

@[export lean_exec_get_core_states]
def ffiGetCoreStates : IO UInt32 := do
  let st ← gState.get
  let cores := (List.range st.cores.size).map fun i =>
    let cs := st.cores[i]!
    match cs with
    | .idle => jsonObj [
        ("core_id", jsonNum i),
        ("state", jsonStr "idle"),
        ("domain_id", jsonNull),
        ("vp_id", jsonNull) ]
    | .runningDomain d v => jsonObj [
        ("core_id", jsonNum i),
        ("state", jsonStr "running"),
        ("domain_id", jsonNum d),
        ("vp_id", jsonNum v) ]
  gResultStr.set (jsonArr cores)
  pure 0

@[export lean_exec_attest]
def ffiAttest (domId : UInt64) : IO UInt32 := do
  let result ← runOp (LeanExec.attestSelf domId.toNat)
  match result with
  | .ok hash =>
    gResultStr.set s!"Attestation hash: 0x{toHex hash}"
    pure 0
  | .error e => returnError e

@[export lean_exec_num_cores]
def ffiNumCores : IO UInt64 := do
  let n ← gNumCores.get
  pure n.toUInt64

end LeanExec.FFI
