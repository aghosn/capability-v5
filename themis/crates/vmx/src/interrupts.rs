//! Software arbitration for the single VM-entry event slot.

const RFLAGS_IF: u64 = 1 << 9;
const BLOCKING_STI_MOV_SS: u64 = 3;
const ENTRY_EVENT_VALID: u64 = 1 << 31;

pub fn can_inject_external_interrupt(rflags: u64, interruptibility: u64, entry_event: u64) -> bool {
    rflags & RFLAGS_IF != 0
        && interruptibility & BLOCKING_STI_MOV_SS == 0
        && entry_event & ENTRY_EVENT_VALID == 0
}

#[derive(Default)]
pub struct PendingExternalInterrupts {
    words: [u64; 4],
}

impl PendingExternalInterrupts {
    pub fn from_words(words: [u64; 4]) -> Self {
        Self { words }
    }

    pub fn into_words(self) -> [u64; 4] {
        self.words
    }

    pub fn insert(&mut self, vector: u8) {
        self.words[usize::from(vector) / 64] |= 1u64 << (vector % 64);
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Preserve the caller's low-vector-first ordering; consume nothing
    /// unless a fresh external interrupt can occupy the entry-event slot.
    pub fn take_lowest(
        &mut self,
        rflags: u64,
        interruptibility: u64,
        entry_event: u64,
    ) -> Option<u8> {
        if !can_inject_external_interrupt(rflags, interruptibility, entry_event) {
            return None;
        }
        for (index, word) in self.words.iter_mut().enumerate() {
            if *word != 0 {
                let bit = word.trailing_zeros();
                *word &= !(1u64 << bit);
                return Some((index * 64 + bit as usize) as u8);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: u64 = 1 << 31;
    const TIMER: u8 = 0xec;
    const DEVICE: u8 = 0x31;

    #[test]
    fn overdue_timer_survives_later_pir_drain() {
        // SWITCH has consumed the deadline and selected its timer for entry.
        let entry_event = VALID | u64::from(TIMER);
        let mut pir = PendingExternalInterrupts::default();
        pir.insert(DEVICE);

        assert_eq!(pir.take_lowest(RFLAGS_IF, 0, entry_event), None);
        assert!(!pir.is_empty());
        // Once the timer entry completes, the device interrupt can follow.
        assert_eq!(pir.take_lowest(RFLAGS_IF, 0, 0), Some(DEVICE));
        assert!(pir.is_empty());
    }

    #[test]
    fn timer_waits_behind_replayed_event() {
        for replay in [
            VALID | u64::from(DEVICE),
            VALID | (2 << 8) | 2,              // NMI
            VALID | (3 << 8) | (1 << 11) | 14, // #PF with error code
        ] {
            assert!(!can_inject_external_interrupt(RFLAGS_IF, 0, replay));
            let mut pending = PendingExternalInterrupts::default();
            pending.insert(TIMER);
            assert_eq!(pending.take_lowest(RFLAGS_IF, 0, replay), None);
            assert_eq!(pending.take_lowest(RFLAGS_IF, 0, 0), Some(TIMER));
        }
    }

    #[test]
    fn masked_or_shadowed_interrupts_remain_pending() {
        for (rflags, blocking) in [(0, 0), (RFLAGS_IF, 1), (RFLAGS_IF, 2)] {
            let mut pending = PendingExternalInterrupts::default();
            pending.insert(TIMER);
            assert_eq!(pending.take_lowest(rflags, blocking, 0), None);
            assert_eq!(pending.take_lowest(RFLAGS_IF, 0, 0), Some(TIMER));
        }
    }

    #[test]
    fn preserves_order_and_bitmap_round_trip() {
        let mut pending = PendingExternalInterrupts::default();
        for vector in [TIMER, DEVICE, 255, 64, DEVICE] {
            pending.insert(vector);
        }
        let mut pending = PendingExternalInterrupts::from_words(pending.into_words());
        for vector in [DEVICE, 64, TIMER, 255] {
            assert_eq!(pending.take_lowest(RFLAGS_IF, 0, 0), Some(vector));
        }
        assert!(pending.is_empty());
    }

    #[test]
    fn invalid_entry_info_does_not_reserve_the_slot() {
        assert!(can_inject_external_interrupt(RFLAGS_IF, 0, 0xec));
    }
}
