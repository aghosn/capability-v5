use capa_engine::capability::*;
use capa_engine::domain::*;
use capa_engine::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Rights, Status as MStatus,
};
use std::cell::RefCell;
use std::rc::Rc;

fn create_root_domain() -> Capability<Domain> {
    let policies = Policies::new(
        !(0 as u64),
        MonitorAPI::all(),
        InterruptPolicy::default_all(),
    );
    let mut capa = Capability::<Domain>::new(Domain::new(policies));
    capa.data.status = Status::Sealed;
    capa
}
fn create_root() -> Capability<MemoryRegion> {
    Capability::<MemoryRegion>::new(MemoryRegion {
        kind: RegionKind::Carve,
        status: MStatus::Exclusive,
        access: Access::new(0, 0x10000, Rights::READ | Rights::WRITE | Rights::EXECUTE),
        attributes: Attributes::NONE,
        remapped: Remapped::Identity,
    })
}

#[test]
fn test_empty_root_domain() {
    let domain = create_root_domain();
    let display_output = format!("{}", domain);
    let expected_output = format!("td0 = Sealed domain()\n|cores: 0xffffffffffffffff\n|mon.api: 0x1fff\n|vec0–255: ALLOWED|VISIBLE, r: 0x0, w: 0x0\n");
    assert_eq!(display_output, expected_output)
}

#[test]
fn test_root_domain_with_root_memory() {
    let mut domain = create_root_domain();
    let region = create_root();
    let reference = Rc::new(RefCell::new(region));
    domain.data.install(CapaWrapper::Region(reference));

    let display_output = format!("{}", domain);
    let expected_output = format!("td0 = Sealed domain(r0)\n|cores: 0xffffffffffffffff\n|mon.api: 0x1fff\n|vec0–255: ALLOWED|VISIBLE, r: 0x0, w: 0x0\nr0 = Exclusive 0x0 0x10000 with RWX mapped Identity\n");
    assert_eq!(display_output, expected_output);
}
