/-
  LeanExec.Monad — The CapaM monad and common helpers.

  CapaM combines error handling (ExceptT CapaError) with state threading
  (StateM ExecState) into a single monad for capability operations.
  All operations are pure: single-threaded, no IO, no locking.
-/
import LeanExec.State

namespace LeanExec

open ThemisCapa

/-- The capability engine monad: state + errors, no IO. -/
abbrev CapaM (α : Type) := ExceptT CapaError (StateM ExecState) α

namespace CapaM

-- ── State access ──

def getState : CapaM ExecState := ExceptT.lift get
def setState (s : ExecState) : CapaM Unit := ExceptT.lift (set s)
def modifyState (f : ExecState → ExecState) : CapaM Unit := ExceptT.lift (modify f)

-- ── Error helpers ──

def throw (e : CapaError) : CapaM α := ExceptT.mk (fun s => (.error e, s))
def guard (cond : Bool) (e : CapaError) : CapaM Unit :=
  if cond then pure () else CapaM.throw e

-- ── Domain helpers ──

def getDomain (id : DomainId) : CapaM ExecDomain := do
  let s ← getState
  match s.getDomain id with
  | some d => pure d
  | none => CapaM.throw .notFound

def setDomain (id : DomainId) (d : ExecDomain) : CapaM Unit :=
  modifyState (·.setDomain id d)

def modifyDomain (id : DomainId) (f : ExecDomain → ExecDomain) : CapaM Unit :=
  modifyState (·.modifyDomain id f)

def allocDomainId : CapaM DomainId := do
  let s ← getState
  let (s', id) := s.allocDomainId
  setState s'
  pure id

-- ── Memory capability helpers ──

def getMemCap (uid : MemCapUid) : CapaM ExecMemCap := do
  let s ← getState
  match s.getMemCap uid with
  | some c => pure c
  | none => CapaM.throw .notFound

def setMemCap (uid : MemCapUid) (c : ExecMemCap) : CapaM Unit :=
  modifyState (·.setMemCap uid c)

def allocCapUid : CapaM MemCapUid := do
  let s ← getState
  let (s', uid) := s.allocCapUid
  setState s'
  pure uid

/-- Look up a memory cap owned by a domain via its local handle. -/
def getDomainMemCap (domId : DomainId) (handle : LocalHandle) : CapaM ExecMemCap := do
  let dom ← getDomain domId
  match dom.lookupMemUid handle with
  | some uid => getMemCap uid
  | none => CapaM.throw .notFound

-- ── Core state helpers ──

def getCurrentCore : CapaM CoreId := do
  let s ← getState
  match s.currentCore with
  | some c => pure c
  | none => CapaM.throw (.invalidOperation "no current core set")

def setCurrentCore (c : Option CoreId) : CapaM Unit :=
  modifyState (fun s => { s with currentCore := c })

def setCoreState (c : CoreId) (cs : CoreState) : CapaM Unit :=
  modifyState (·.setCoreState c cs)

-- ── VP register helpers ──

def getVpReg (domId : DomainId) (vpId : VpId) (regId : Nat) : CapaM Nat := do
  let s ← getState
  pure (s.getVpReg domId vpId regId |>.getD 0)

def setVpReg (domId : DomainId) (vpId : VpId) (regId : Nat) (val : Nat) : CapaM Unit :=
  modifyState (·.setVpReg domId vpId regId val)

-- ── Precondition helpers ──

/-- Require a domain to be sealed. -/
def requireSealed (dom : ExecDomain) : CapaM Unit :=
  guard dom.isSealed .domainNotSealed

/-- Require a domain to be unsealed. -/
def requireUnsealed (dom : ExecDomain) : CapaM Unit :=
  guard dom.isUnsealed .domainSealed

/-- Require a domain is not revoked. -/
def requireNotRevoked (dom : ExecDomain) : CapaM Unit :=
  guard (!dom.isRevoked) .domainRevoked

/-- Require a handle is not frozen. -/
def requireNotFrozen (dom : ExecDomain) (h : LocalHandle) : CapaM Unit :=
  guard (!dom.isFrozen h) .permissionDenied

/-- Require an API permission. -/
def requireApi (dom : ExecDomain) (perm : MonitorAPI → Bool) : CapaM Unit :=
  guard (perm dom.policy.api) .apiNotAllowed

-- ── Execution ──

/-- Run a CapaM computation on a state, returning result and final state. -/
def run (m : CapaM α) (s : ExecState) : Except CapaError α × ExecState :=
  StateT.run (ExceptT.run m) s

/-- Run a CapaM computation, extracting just the result. -/
def eval (m : CapaM α) (s : ExecState) : Except CapaError α :=
  (run m s).1

end CapaM

end LeanExec
