extern crate alloc;

use alloc::vec::Vec;

pub(crate) fn merge_register_writes<R: PartialEq>(
    pending: &mut Vec<(R, u64)>,
    writes: impl IntoIterator<Item = (R, u64)>,
    can_write: impl Fn(&R) -> bool,
) {
    for (reg, value) in writes {
        if !can_write(&reg) {
            continue;
        }
        if let Some((_, old_value)) = pending.iter_mut().find(|(old_reg, _)| *old_reg == reg) {
            *old_value = value;
        } else {
            pending.push((reg, value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_runtime_writes_preserve_frozen_initialization() {
        let mut pending = Vec::new();
        merge_register_writes(&mut pending, [(0, 0x100000), (1, 0x9000)], |_| true);
        merge_register_writes(&mut pending, [(0, 0xbad), (2, 0xbad)], |_| false);
        merge_register_writes(&mut pending, [], |_| false);
        assert_eq!(pending, [(0, 0x100000), (1, 0x9000)]);
    }

    #[test]
    fn permitted_runtime_writes_replace_only_selected_registers() {
        let mut pending = Vec::new();
        merge_register_writes(&mut pending, [(0, 10), (1, 20)], |_| true);
        merge_register_writes(&mut pending, [(0, 30), (1, 40), (2, 50)], |reg| *reg != 0);
        assert_eq!(pending, [(0, 10), (1, 40), (2, 50)]);
    }

    #[test]
    fn setup_retry_merges_new_values_without_duplicate_entries() {
        let mut pending = Vec::new();
        merge_register_writes(&mut pending, [(0, 10), (1, 20)], |_| true);
        merge_register_writes(&mut pending, [(0, 30), (2, 40)], |_| true);
        assert_eq!(pending, [(0, 30), (1, 20), (2, 40)]);
    }
}
