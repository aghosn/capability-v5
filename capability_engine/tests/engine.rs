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

#[test]
fn test_engine_create_root_and_simple_child() {
    // Initial setup
    let engine = Engine::new();
    let mut root_domain = create_root_domain();
    let root_region = create_root_region();
    let ref_mem = Rc::new(RefCell::new(root_region));
    let ref_region = root_domain.data.install(CapaWrapper::Region(ref_mem));
    let ref_td = Rc::new(RefCell::new(root_domain));

    // Create a child.
    let child_td = engine
        .create(
            ref_td.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Create some regions.
    let ref_aliased = engine
        .alias(
            ref_td.clone(),
            ref_region,
            &Access::new(0x0, 0x2000, Rights::READ | Rights::WRITE),
        )
        .unwrap();
    let ref_carved = engine
        .carve(
            ref_td.clone(),
            ref_region,
            &Access::new(
                0x2000,
                0x2000,
                Rights::READ | Rights::WRITE | Rights::EXECUTE,
            ),
        )
        .unwrap();

    // Send the region, this moves the references.
    engine.send(ref_td.clone(), child_td, ref_aliased).unwrap();
    engine.send(ref_td.clone(), child_td, ref_carved).unwrap();

    // Seal
    engine.seal(ref_td.clone(), child_td).unwrap();

    // Print the domain.
    let display = format!("{}", ref_td.borrow());
    let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0–255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1,r2)
|cores: 0x1
|mon.api: 0x1fff
|vec0–255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x0 0x2000 with RW_ for r1
| Carve at 0x2000 0x4000 with RWX for r2
r1 = Aliased 0x0 0x2000 with RW_ mapped Identity
r2 = Exclusive 0x2000 0x4000 with RWX mapped Identity
"#;

    assert_eq!(display, expected);
}
