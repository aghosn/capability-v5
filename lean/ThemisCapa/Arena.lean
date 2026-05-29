/-
  ThemisCapa.Arena — Insertion-ordered association-list "finmap".

  Avoids Mathlib. Uses direct recursive definitions so that proofs reduce
  by structural induction with no surprises from library lemma renames.
-/
namespace ThemisCapa

/-- Direct recursive lookup over an assoc-list. -/
def assocLookup {α β : Type} [DecidableEq α] :
    List (α × β) → α → Option β
  | [], _ => none
  | (k', v) :: rest, k => if k' = k then some v else assocLookup rest k

/-- Functional update of every entry whose key matches. Preserves order. -/
def assocUpdate {α β : Type} [DecidableEq α] (f : β → β) (k : α) :
    List (α × β) → List (α × β)
  | [] => []
  | (k', v) :: rest =>
    let head := if k' = k then (k', f v) else (k', v)
    head :: assocUpdate f k rest

structure Arena (α β : Type) [DecidableEq α] where
  entries : List (α × β)

namespace Arena

variable {α β : Type} [DecidableEq α]

def empty : Arena α β := ⟨[]⟩

def find? (a : Arena α β) (k : α) : Option β := assocLookup a.entries k

def keys (a : Arena α β) : List α := a.entries.map Prod.fst

def insert (a : Arena α β) (k : α) (v : β) : Arena α β :=
  ⟨(k, v) :: a.entries⟩

def update (a : Arena α β) (k : α) (f : β → β) : Arena α β :=
  ⟨assocUpdate f k a.entries⟩

/-- The arena has no duplicate keys. Maintained by always inserting at
    a fresh key (monotonic counter discipline). -/
def UniqueKeys (a : Arena α β) : Prop :=
  (a.entries.map Prod.fst).Nodup

/-! ### Core lookup lemmas -/

@[simp] theorem find?_insert_same (a : Arena α β) (k : α) (v : β) :
    (a.insert k v).find? k = some v := by
  simp [insert, find?, assocLookup]

theorem find?_insert_other (a : Arena α β) (k k' : α) (v : β) (h : k' ≠ k) :
    (a.insert k v).find? k' = a.find? k' := by
  simp [insert, find?, assocLookup]
  intro hk
  exact absurd hk.symm h

/-- After updating at `k`, looking up `k` produces `f` applied to the
    previous value (under uniqueness of keys). -/
theorem find?_update_same (a : Arena α β) (k : α) (f : β → β) {v : β}
    (hk : a.find? k = some v) :
    (a.update k f).find? k = some (f v) := by
  obtain ⟨es⟩ := a
  simp only [find?, update] at hk ⊢
  induction es with
  | nil => simp [assocLookup] at hk
  | cons p ps ih =>
    rcases p with ⟨k', v'⟩
    simp [assocLookup, assocUpdate] at hk ⊢
    by_cases hp : k' = k
    · simp [hp] at hk ⊢
      cases hk; rfl
    · simp [hp] at hk ⊢
      exact ih hk

theorem find?_update_other (a : Arena α β) (k k' : α) (f : β → β) (h : k' ≠ k) :
    (a.update k f).find? k' = a.find? k' := by
  obtain ⟨es⟩ := a
  simp only [find?, update]
  induction es with
  | nil => simp [assocUpdate, assocLookup]
  | cons p ps ih =>
    rcases p with ⟨kp, vp⟩
    simp [assocUpdate, assocLookup]
    by_cases hp : kp = k
    · simp [hp]
      have hne : ¬ k = k' := fun heq => h heq.symm
      simp [hne]
      exact ih
    · simp [hp]
      by_cases hp' : kp = k'
      · simp [hp']
      · simp [hp']; exact ih

theorem keys_insert (a : Arena α β) (k : α) (v : β) :
    (a.insert k v).keys = k :: a.keys := by
  simp [insert, keys]

theorem keys_update (a : Arena α β) (k : α) (f : β → β) :
    (a.update k f).keys = a.keys := by
  obtain ⟨es⟩ := a
  simp only [update, keys]
  induction es with
  | nil => simp [assocUpdate]
  | cons p ps ih =>
    rcases p with ⟨kp, vp⟩
    simp [assocUpdate]
    by_cases hp : kp = k <;> simp [hp, ih]

theorem insert_unique_keys (a : Arena α β) (k : α) (v : β)
    (hu : a.UniqueKeys) (hfresh : k ∉ a.keys) :
    (a.insert k v).UniqueKeys := by
  simp only [UniqueKeys, insert]
  simp only [List.map_cons]
  exact List.nodup_cons.mpr ⟨by simpa [keys] using hfresh, hu⟩

theorem update_unique_keys (a : Arena α β) (k : α) (f : β → β)
    (hu : a.UniqueKeys) : (a.update k f).UniqueKeys := by
  show ((a.update k f).keys).Nodup
  rw [keys_update]
  exact hu

theorem find?_update_eq_map (a : Arena α β) (k : α) (f : β → β) :
    (a.update k f).find? k = (a.find? k).map f := by
  obtain ⟨es⟩ := a
  simp only [find?, update]
  induction es with
  | nil => simp [assocLookup, assocUpdate]
  | cons p ps ih =>
    rcases p with ⟨kp, vp⟩
    simp only [assocUpdate, assocLookup]
    by_cases hp : kp = k
    · simp [hp]
    · simp [hp]; exact ih

/-- If `find?` returns `some v` at key `k`, then `k` appears in `keys`. -/
theorem mem_keys_of_find?_some (a : Arena α β) (k : α) (v : β)
    (h : a.find? k = some v) : k ∈ a.keys := by
  obtain ⟨es⟩ := a
  show k ∈ List.map Prod.fst es
  simp only [find?] at h
  induction es with
  | nil => simp [assocLookup] at h
  | cons p ps ih =>
    rcases p with ⟨k', v'⟩
    simp only [assocLookup] at h
    split at h
    · rename_i hk; subst hk
      exact List.mem_cons_self
    · rename_i hk
      exact List.mem_cons.mpr (Or.inr (ih h))

/-! ### Remove -/

/-- Drop every entry whose key matches. Preserves order of survivors. -/
def assocRemove {α β : Type} [DecidableEq α] (k : α) :
    List (α × β) → List (α × β)
  | [] => []
  | (k', v) :: rest =>
    if k' = k then assocRemove k rest
    else (k', v) :: assocRemove k rest

def remove (a : Arena α β) (k : α) : Arena α β := ⟨assocRemove k a.entries⟩

theorem find?_remove_same (a : Arena α β) (k : α) :
    (a.remove k).find? k = none := by
  obtain ⟨es⟩ := a
  show assocLookup (assocRemove k es) k = none
  induction es with
  | nil => simp [assocRemove, assocLookup]
  | cons p ps ih =>
    rcases p with ⟨k', v⟩
    simp only [assocRemove]
    by_cases hp : k' = k
    · simp [hp, ih]
    · simp [hp, assocLookup, ih]

theorem find?_remove_other (a : Arena α β) (k k' : α) (h : k' ≠ k) :
    (a.remove k).find? k' = a.find? k' := by
  obtain ⟨es⟩ := a
  show assocLookup (assocRemove k es) k' = assocLookup es k'
  induction es with
  | nil => simp [assocRemove, assocLookup]
  | cons p ps ih =>
    rcases p with ⟨kp, vp⟩
    simp only [assocRemove, assocLookup]
    by_cases hp : kp = k
    · subst hp
      have : ¬ kp = k' := fun heq => h heq.symm
      simp [this, ih]
    · simp only [hp, if_false, assocLookup]
      by_cases hp' : kp = k'
      · simp [hp']
      · simp [hp']; exact ih

theorem keys_remove (a : Arena α β) (k : α) :
    (a.remove k).keys = a.keys.filter (· ≠ k) := by
  obtain ⟨es⟩ := a
  show List.map Prod.fst (assocRemove k es) = (List.map Prod.fst es).filter (· ≠ k)
  induction es with
  | nil => simp [assocRemove]
  | cons p ps ih =>
    rcases p with ⟨kp, vp⟩
    simp only [assocRemove, List.map_cons, List.filter_cons]
    by_cases hp : kp = k
    · simp [hp, ih]
    · simp [hp, ih]

theorem remove_unique_keys (a : Arena α β) (k : α) (hu : a.UniqueKeys) :
    (a.remove k).UniqueKeys := by
  show ((a.remove k).keys).Nodup
  rw [keys_remove]
  exact hu.filter _

theorem mem_keys_remove_iff (a : Arena α β) (k k' : α) :
    k' ∈ (a.remove k).keys ↔ k' ≠ k ∧ k' ∈ a.keys := by
  rw [keys_remove, List.mem_filter]
  simp [And.comm]

end Arena
end ThemisCapa
