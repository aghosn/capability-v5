use capa_engine::capability::*;
use capa_engine::domain::*;
use capa_engine::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Rights, Status as MStatus,
};
use capa_engine::Engine;
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
fn create_root_region() -> Capability<MemoryRegion> {
    Capability::<MemoryRegion>::new(MemoryRegion {
        kind: RegionKind::Carve,
        status: MStatus::Exclusive,
        access: Access::new(0, 0x10000, Rights::READ | Rights::WRITE | Rights::EXECUTE),
        attributes: Attributes::NONE,
        remapped: Remapped::Identity,
    })
}

fn setup_engine_with_root() -> (
    Engine,
    CapaRef<Domain>,
    CapaRef<MemoryRegion>,
    LocalCapa, // ref_region returned by `add_root_region`
) {
    let engine = Engine::new();
    let root_domain = create_root_domain();
    let root_region = create_root_region();

    let ref_td = Rc::new(RefCell::new(root_domain));
    let ref_mem = Rc::new(RefCell::new(root_region));
    let ref_region = engine.add_root_region(&ref_td, &ref_mem).unwrap();

    (engine, ref_td, ref_mem, ref_region)
}

#[test]
fn test_serialize_memory() {
    let (engine, td0, _r0, td0_r0) = setup_engine_with_root();

    let region = td0
        .borrow()
        .data
        .capabilities
        .get(&td0_r0)
        .unwrap()
        .as_region()
        .unwrap();
}
