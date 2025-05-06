pub mod core;
pub mod server;

fn is_core_subset(reference: u64, other: u64) -> bool {
    (reference & other) == other
}
