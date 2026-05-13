//! Workload modules — each is a self-contained app_main selected via feature.

#[cfg(feature = "app-smoke")]
pub mod smoke;

#[cfg(feature = "app-timer")]
pub mod timer;

#[cfg(feature = "app-memory")]
pub mod memory;
