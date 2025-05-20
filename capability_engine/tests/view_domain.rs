use capa_engine::core::capability::*;
use capa_engine::core::domain::*;
use capa_engine::core::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Rights, Status as MStatus, ViewRegion,
};
use capa_engine::server::engine::Engine;
use capa_engine::EngineInterface;
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
fn test_view_root_td() {
    // Initial setup
    let (_engine, td0, r0, _) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    // The view we expect.
    let expected = vec![ViewRegion::new(
        Access::new(0, 0x10000, Rights::all()),
        Remapped::Identity,
    )];

    let obtained = td0.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_root_td_carve() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let carve_access = Access::new(0x1000, 0x5000, Rights::READ | Rights::WRITE);
    let _carved = engine.carve(td0.clone(), td0_r0, &carve_access).unwrap();

    // The view we expect.
    let expected = vec![
        ViewRegion::new(Access::new(0x0, 0x1000, Rights::all()), Remapped::Identity),
        ViewRegion::new(carve_access, Remapped::Identity),
        ViewRegion::new(
            Access::new(0x6000, 0xa000, Rights::all()),
            Remapped::Identity,
        ),
    ];

    let obtained = td0.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_root_td_carve_no_change() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let carve_access = Access::new(0x1000, 0x5000, Rights::all());
    let _carved = engine.carve(td0.clone(), td0_r0, &carve_access).unwrap();

    // The view we expect.
    let expected = vec![ViewRegion::new(
        Access::new(0x0, 0x10000, Rights::all()),
        Remapped::Identity,
    )];

    let obtained = td0.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_root_td_alias() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let alias_access = Access::new(0x1000, 0x5000, Rights::READ | Rights::WRITE);
    let _aliased = engine.alias(td0.clone(), td0_r0, &alias_access).unwrap();

    // The view we expect.
    let expected = vec![ViewRegion::new(
        Access::new(0x0, 0x10000, Rights::all()),
        Remapped::Identity,
    )];

    let obtained = td0.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_sending_alias() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let alias_access = Access::new(0x1000, 0x5000, Rights::READ | Rights::WRITE);
    let aliased = engine.alias(td0.clone(), td0_r0, &alias_access).unwrap();

    // Create a child.
    let child_td = engine
        .create(
            &td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Send the capa to the child.
    engine
        .send(
            td0.clone(),
            child_td,
            aliased,
            Remapped::Identity,
            Attributes::empty(),
        )
        .unwrap();

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // The view we expect for td0.
    let expected = vec![ViewRegion::new(
        Access::new(0x0, 0x10000, Rights::all()),
        Remapped::Identity,
    )];

    let obtained = td0.borrow().view().unwrap();
    assert_eq!(obtained, expected);

    // The view we expect for the child.
    let child = td0
        .borrow()
        .data
        .capabilities
        .get(&child_td)
        .unwrap()
        .as_domain()
        .unwrap();

    let expected = vec![ViewRegion::new(alias_access, Remapped::Identity)];
    let obtained = child.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_sending_carve() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let carve_access = Access::new(0x1000, 0x5000, Rights::READ | Rights::WRITE);
    let carved = engine.carve(td0.clone(), td0_r0, &carve_access).unwrap();

    // Create a child.
    let child_td = engine
        .create(
            &td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Send the capa to the child.
    engine
        .send(
            td0.clone(),
            child_td,
            carved,
            Remapped::Identity,
            Attributes::empty(),
        )
        .unwrap();

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // The view we expect for td0.
    let expected = vec![
        ViewRegion::new(Access::new(0x0, 0x1000, Rights::all()), Remapped::Identity),
        ViewRegion::new(
            Access::new(0x6000, 0xa000, Rights::all()),
            Remapped::Identity,
        ),
    ];

    let obtained = td0.borrow().view().unwrap();
    assert_eq!(obtained, expected);

    // The view we expect for the child.
    let child = td0
        .borrow()
        .data
        .capabilities
        .get(&child_td)
        .unwrap()
        .as_domain()
        .unwrap();

    let expected = vec![ViewRegion::new(carve_access, Remapped::Identity)];
    let obtained = child.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_sending_carve_begin() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let carve_access = Access::new(0x0, 0x1000, Rights::READ | Rights::WRITE);
    let carved = engine.carve(td0.clone(), td0_r0, &carve_access).unwrap();

    // Create a child.
    let child_td = engine
        .create(
            &td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Send the capa to the child.
    engine
        .send(
            td0.clone(),
            child_td,
            carved,
            Remapped::Identity,
            Attributes::empty(),
        )
        .unwrap();

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // The view we expect for td0.
    let expected = vec![ViewRegion::new(
        Access::new(0x1000, 0xf000, Rights::all()),
        Remapped::Identity,
    )];

    let obtained = td0.borrow().view().unwrap();
    assert_eq!(obtained, expected);

    // The view we expect for the child.
    let child = td0
        .borrow()
        .data
        .capabilities
        .get(&child_td)
        .unwrap()
        .as_domain()
        .unwrap();

    let expected = vec![ViewRegion::new(carve_access, Remapped::Identity)];
    let obtained = child.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_sending_carve_end() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let carve_access = Access::new(0xf000, 0x1000, Rights::READ | Rights::WRITE);
    let carved = engine.carve(td0.clone(), td0_r0, &carve_access).unwrap();

    // Create a child.
    let child_td = engine
        .create(
            &td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Send the capa to the child.
    engine
        .send(
            td0.clone(),
            child_td,
            carved,
            Remapped::Identity,
            Attributes::empty(),
        )
        .unwrap();

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // The view we expect for td0.
    let expected = vec![ViewRegion::new(
        Access::new(0x0, 0xf000, Rights::all()),
        Remapped::Identity,
    )];

    let obtained = td0.borrow().view().unwrap();
    assert_eq!(obtained, expected);

    // The view we expect for the child.
    let child = td0
        .borrow()
        .data
        .capabilities
        .get(&child_td)
        .unwrap()
        .as_domain()
        .unwrap();

    let expected = vec![ViewRegion::new(carve_access, Remapped::Identity)];
    let obtained = child.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_child_middle_overlap() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let alias_access = Access::new(0x0, 0x5000, Rights::READ | Rights::WRITE);
    let alias = engine.alias(td0.clone(), td0_r0, &alias_access).unwrap();

    let middle_access = Access::new(0x2000, 0x1000, Rights::all());
    let middle = engine.alias(td0.clone(), td0_r0, &middle_access).unwrap();

    // Create a child.
    let child_td = engine
        .create(
            &td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Send the capa to the child.
    engine
        .send(
            td0.clone(),
            child_td,
            alias,
            Remapped::Identity,
            Attributes::empty(),
        )
        .unwrap();

    engine
        .send(
            td0.clone(),
            child_td,
            middle,
            Remapped::Identity,
            Attributes::empty(),
        )
        .unwrap();

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // The view we expect for the child.
    let child = td0
        .borrow()
        .data
        .capabilities
        .get(&child_td)
        .unwrap()
        .as_domain()
        .unwrap();

    let expected = vec![
        ViewRegion::new(
            Access::new(0, 0x2000, Rights::READ | Rights::WRITE),
            Remapped::Identity,
        ),
        ViewRegion::new(
            Access::new(0x2000, 0x1000, Rights::all()),
            Remapped::Identity,
        ),
        ViewRegion::new(
            Access::new(0x3000, 0x2000, Rights::READ | Rights::WRITE),
            Remapped::Identity,
        ),
    ];
    let obtained = child.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_child_middle_overlap_remap() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let alias_access = Access::new(0x0, 0x5000, Rights::READ | Rights::WRITE);
    let alias = engine.alias(td0.clone(), td0_r0, &alias_access).unwrap();

    let middle_access = Access::new(0x2000, 0x1000, Rights::all());
    let middle = engine.alias(td0.clone(), td0_r0, &middle_access).unwrap();

    // Create a child.
    let child_td = engine
        .create(
            &td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Send the capa to the child.
    engine
        .send(
            td0.clone(),
            child_td,
            alias,
            Remapped::Remapped(0x30000),
            Attributes::empty(),
        )
        .unwrap();

    engine
        .send(
            td0.clone(),
            child_td,
            middle,
            Remapped::Remapped(0x32000),
            Attributes::empty(),
        )
        .unwrap();

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // The view we expect for the child.
    let child = td0
        .borrow()
        .data
        .capabilities
        .get(&child_td)
        .unwrap()
        .as_domain()
        .unwrap();

    let expected = vec![
        ViewRegion::new(
            Access::new(0, 0x2000, Rights::READ | Rights::WRITE),
            Remapped::Remapped(0x30000),
        ),
        ViewRegion::new(
            Access::new(0x2000, 0x1000, Rights::all()),
            Remapped::Remapped(0x32000),
        ),
        ViewRegion::new(
            Access::new(0x3000, 0x2000, Rights::READ | Rights::WRITE),
            Remapped::Remapped(0x33000),
        ),
    ];
    let obtained = child.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_child_start_overlap_remap() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let alias_access = Access::new(0x0, 0x5000, Rights::READ | Rights::WRITE);
    let alias = engine.alias(td0.clone(), td0_r0, &alias_access).unwrap();

    let start_access = Access::new(0x0, 0x1000, Rights::all());
    let start = engine.alias(td0.clone(), td0_r0, &start_access).unwrap();

    // Create a child.
    let child_td = engine
        .create(
            &td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Send the capa to the child.
    engine
        .send(
            td0.clone(),
            child_td,
            alias,
            Remapped::Remapped(0x30000),
            Attributes::empty(),
        )
        .unwrap();

    engine
        .send(
            td0.clone(),
            child_td,
            start,
            Remapped::Remapped(0x30000),
            Attributes::empty(),
        )
        .unwrap();

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // The view we expect for the child.
    let child = td0
        .borrow()
        .data
        .capabilities
        .get(&child_td)
        .unwrap()
        .as_domain()
        .unwrap();

    let expected = vec![
        ViewRegion::new(
            Access::new(0, 0x1000, Rights::all()),
            Remapped::Remapped(0x30000),
        ),
        ViewRegion::new(
            Access::new(0x1000, 0x4000, Rights::READ | Rights::WRITE),
            Remapped::Remapped(0x31000),
        ),
    ];
    let obtained = child.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}

#[test]
fn test_view_child_end_overlap_remap() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let alias_access = Access::new(0x0, 0x5000, Rights::READ | Rights::WRITE);
    let alias = engine.alias(td0.clone(), td0_r0, &alias_access).unwrap();

    let start_access = Access::new(0x4000, 0x1000, Rights::all());
    let start = engine.alias(td0.clone(), td0_r0, &start_access).unwrap();

    // Create a child.
    let child_td = engine
        .create(
            &td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Send the capa to the child.
    engine
        .send(
            td0.clone(),
            child_td,
            alias,
            Remapped::Remapped(0x30000),
            Attributes::empty(),
        )
        .unwrap();

    engine
        .send(
            td0.clone(),
            child_td,
            start,
            Remapped::Remapped(0x34000),
            Attributes::empty(),
        )
        .unwrap();

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // The view we expect for the child.
    let child = td0
        .borrow()
        .data
        .capabilities
        .get(&child_td)
        .unwrap()
        .as_domain()
        .unwrap();

    let expected = vec![
        ViewRegion::new(
            Access::new(0, 0x4000, Rights::READ | Rights::WRITE),
            Remapped::Remapped(0x30000),
        ),
        ViewRegion::new(
            Access::new(0x4000, 0x1000, Rights::all()),
            Remapped::Remapped(0x34000),
        ),
    ];
    let obtained = child.borrow().view().unwrap();
    assert_eq!(obtained, expected);
}
