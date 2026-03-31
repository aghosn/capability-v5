/-
  LeanExec.State — Global executable state for the capability engine.
-/
import LeanExec.Types

namespace LeanExec

open ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § ExecState — the complete mutable state of the capability system
-- ════════════════════════════════════════════════════════════════════

/-- The complete state of the executable capability engine.
    All memory capabilities and domains are stored in flat maps
    indexed by unique IDs, enabling efficient lookup and update. -/
structure ExecState where
  /-- All domains, keyed by DomainId. -/
  domains      : List (DomainId × ExecDomain)
  /-- All memory capabilities (flat store), keyed by MemCapUid. -/
  memCaps      : List (MemCapUid × ExecMemCap)
  /-- Per-core scheduling state. -/
  cores        : Array CoreState
  /-- Next domain ID to allocate. -/
  nextDomainId : DomainId
  /-- Next memory capability UID to allocate. -/
  nextCapUid   : MemCapUid
  /-- Which core is currently executing (for VP-aware operations). -/
  currentCore  : Option CoreId
  /-- VP register file: (domainId, vpId, regId) → value.
      Encoded as (domainId * 1000000 + vpId * 1000 + regId) → value. -/
  vpRegisters  : List (Nat × Nat)
  /-- Total number of registers per VP (for bounds checking). -/
  registerCount : Nat
deriving Repr

deriving instance Inhabited for ThemisCapa.CoreState

namespace ExecState

def empty (numCores : Nat) : ExecState :=
  { domains := []
    memCaps := []
    cores := (List.replicate numCores CoreState.idle).toArray
    nextDomainId := 0
    nextCapUid := 0
    currentCore := none
    vpRegisters := []
    registerCount := 256 }

-- ── Domain lookups ──

def getDomain (s : ExecState) (id : DomainId) : Option ExecDomain :=
  (s.domains.find? (fun p => p.1 == id)).map Prod.snd

def setDomain (s : ExecState) (id : DomainId) (d : ExecDomain) : ExecState :=
  if s.domains.any (fun p => p.1 == id) then
    { s with domains := s.domains.map (fun p => if p.1 == id then (id, d) else p) }
  else
    { s with domains := s.domains ++ [(id, d)] }

def removeDomain (s : ExecState) (id : DomainId) : ExecState :=
  { s with domains := s.domains.filter (fun p => p.1 != id) }

def modifyDomain (s : ExecState) (id : DomainId) (f : ExecDomain → ExecDomain) : ExecState :=
  { s with domains := s.domains.map (fun p => if p.1 == id then (id, f p.2) else p) }

def allocDomainId (s : ExecState) : ExecState × DomainId :=
  ({ s with nextDomainId := s.nextDomainId + 1 }, s.nextDomainId)

-- ── Memory capability lookups ──

def getMemCap (s : ExecState) (uid : MemCapUid) : Option ExecMemCap :=
  (s.memCaps.find? (fun p => p.1 == uid)).map Prod.snd

def setMemCap (s : ExecState) (uid : MemCapUid) (c : ExecMemCap) : ExecState :=
  if s.memCaps.any (fun p => p.1 == uid) then
    { s with memCaps := s.memCaps.map (fun p => if p.1 == uid then (uid, c) else p) }
  else
    { s with memCaps := s.memCaps ++ [(uid, c)] }

def removeMemCap (s : ExecState) (uid : MemCapUid) : ExecState :=
  { s with memCaps := s.memCaps.filter (fun p => p.1 != uid) }

def allocCapUid (s : ExecState) : ExecState × MemCapUid :=
  ({ s with nextCapUid := s.nextCapUid + 1 }, s.nextCapUid)

-- ── Core state ──

def getCoreState (s : ExecState) (c : CoreId) : Option CoreState :=
  if c < s.cores.size then some (s.cores[c]!) else none

def setCoreState (s : ExecState) (c : CoreId) (cs : CoreState) : ExecState :=
  if c < s.cores.size then { s with cores := s.cores.set! c cs } else s

-- ── VP registers ──

private def regKey (domId : DomainId) (vpId : VpId) (regId : Nat) : Nat :=
  domId * 1000000 + vpId * 1000 + regId

def getVpReg (s : ExecState) (domId : DomainId) (vpId : VpId) (regId : Nat) : Option Nat :=
  (s.vpRegisters.find? (fun p => p.1 == regKey domId vpId regId)).map Prod.snd

def setVpReg (s : ExecState) (domId : DomainId) (vpId : VpId) (regId : Nat) (val : Nat) : ExecState :=
  let key := regKey domId vpId regId
  if s.vpRegisters.any (fun p => p.1 == key) then
    { s with vpRegisters := s.vpRegisters.map (fun p => if p.1 == key then (key, val) else p) }
  else
    { s with vpRegisters := s.vpRegisters ++ [(key, val)] }

-- ── Helpers ──

/-- Find which domain is running on a core. -/
def domainOnCore (s : ExecState) (c : CoreId) : Option DomainId :=
  match s.getCoreState c with
  | some (.runningDomain d _) => some d
  | _ => none

/-- Find the first non-revoked ancestor of a domain (for revocation fallback). -/
partial def findFallback (s : ExecState) (domId : DomainId) : DomainId :=
  match s.getDomain domId with
  | some d => match d.parentDomId with
    | some pid => match s.getDomain pid with
      | some parent => if parent.isRevoked then s.findFallback pid else pid
      | none => 0
    | none => 0
  | none => 0

/-- Collect all memory capability UIDs in a subtree rooted at uid. -/
partial def collectSubtree (s : ExecState) (uid : MemCapUid) : List MemCapUid :=
  match s.getMemCap uid with
  | some cap => uid :: cap.childUids.toList.flatMap (s.collectSubtree ·)
  | none => []

end ExecState

end LeanExec
