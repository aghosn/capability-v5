use capa_engine::capability::*;
use capa_engine::domain::*;
use capa_engine::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Rights, Status as MStatus, ViewRegion,
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
fn test_remap_carve() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    // Create a child.
    let child_td = engine
        .create(
            td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Create a region and send it with a remap
    let carve_access = Access::new(0x0, 0x1000, Rights::all());
    let carved = engine.carve(td0.clone(), td0_r0, &carve_access).unwrap();

    // Send it with a remap.
    engine
        .send(td0.clone(), child_td, carved, Remapped::Remapped(0x2000))
        .unwrap();

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // Now check the views and attestations.
    let display = format!("{}", td0.borrow());
    let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x1000 with RWX for r1
r1 = Exclusive 0x0 0x1000 with RWX mapped Remapped(0x2000)
"#;
    assert_eq!(display, expected);

    // Check the views.
    let view = td0.borrow().view().unwrap();
    let expected = vec![ViewRegion::new(
        Access::new(0x1000, 0xf000, Rights::all()),
        Remapped::Identity,
    )];

    assert_eq!(view, expected);
    // Get the child and check the view.
    {
        let child = td0
            .borrow()
            .data
            .capabilities
            .get(&child_td)
            .unwrap()
            .as_domain()
            .unwrap();
        let view = child.borrow().view().unwrap();
        let expected = vec![ViewRegion::new(
            Access::new(0x0, 0x1000, Rights::all()),
            Remapped::Remapped(0x2000),
        )];
        assert_eq!(view, expected);

        let display = format!("{}", child.borrow());
        let expected = r#"td0 = Sealed domain(r0)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x1000 with RWX mapped Remapped(0x2000)
"#;
        assert_eq!(display, expected);
    }
    // Now let's cleanup.
    engine.revoke(td0.clone(), child_td, 0).unwrap();
    let view = td0.borrow().view().unwrap();
    let expected = vec![ViewRegion::new(
        Access::new(0x0, 0x10000, Rights::all()),
        Remapped::Identity,
    )];
    assert_eq!(view, expected);
}

#[test]
fn test_remap_illegal() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    // Create a child.
    let child_td = engine
        .create(
            td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Create a region and send it with a remap
    let alias_access = Access::new(0x0, 0x2000, Rights::all());
    let alias2_access = Access::new(0x0, 0x1000, Rights::all());
    let alias = engine.alias(td0.clone(), td0_r0, &alias_access).unwrap();
    let alias2 = engine.alias(td0.clone(), td0_r0, &alias2_access).unwrap();

    // Send them with a remap.
    engine
        .send(td0.clone(), child_td, alias, Remapped::Remapped(0x10000))
        .unwrap();
    engine
        .send(td0.clone(), child_td, alias2, Remapped::Remapped(0x10000))
        .unwrap();
    let res = engine.send(td0.clone(), child_td, alias2, Remapped::Remapped(0x11000));
    assert!(res.is_err());

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // Check revoking makes all things good.
    engine.revoke(td0.clone(), child_td, 0).unwrap();

    let view = td0.borrow().view().unwrap();
    let expected = vec![ViewRegion::new(
        Access::new(0x0, 0x10000, Rights::all()),
        Remapped::Identity,
    )];
    assert_eq!(view, expected);
}

#[test]
fn test_remap_illegal_in_hole() {
    // Initial setup
    let (engine, td0, r0, td0_r0) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&td0), 1);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    // Create a child.
    let child_td = engine
        .create(
            td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Create a region and send it with a remap
    let alias_access = Access::new(0x0, 0x3000, Rights::all());
    let alias = engine.alias(td0.clone(), td0_r0, &alias_access).unwrap();
    let plug_access = Access::new(0x4000, 0x1000, Rights::all());
    let plug = engine.alias(td0.clone(), td0_r0, &plug_access).unwrap();

    // Send them with a remap.
    engine
        .send(td0.clone(), child_td, alias, Remapped::Remapped(0x10000))
        .unwrap();

    // Seal the child.
    engine.seal(td0.clone(), child_td).unwrap();

    // Let the child create a hole in his address space.
    {
        let child = td0
            .borrow()
            .data
            .capabilities
            .get(&child_td)
            .unwrap()
            .as_domain()
            .unwrap();

        let carve_access = Access::new(0x1000, 0x1000, Rights::READ | Rights::WRITE);
        let carve = engine.carve(child.clone(), 1, &carve_access).unwrap();

        let view = child.borrow().view().unwrap();
        let expected = vec![
            ViewRegion::new(
                Access::new(0x0, 0x1000, Rights::all()),
                Remapped::Remapped(0x10000),
            ),
            ViewRegion::new(
                Access::new(0x1000, 0x1000, Rights::READ | Rights::WRITE),
                Remapped::Remapped(0x11000),
            ),
            ViewRegion::new(
                Access::new(0x2000, 0x1000, Rights::all()),
                Remapped::Remapped(0x12000),
            ),
        ];
        assert_eq!(view, expected);

        // Create the grandchild.
        let gc_td = engine
            .create(
                child.clone(),
                1,
                MonitorAPI::all(),
                InterruptPolicy::default_none(),
            )
            .unwrap();

        engine
            .send(child.clone(), gc_td, carve, Remapped::Identity)
            .unwrap();
        engine.seal(child.clone(), gc_td).unwrap();

        // Now check the view.
        let view = child.borrow().view().unwrap();
        let expected = vec![
            ViewRegion::new(
                Access::new(0x0, 0x1000, Rights::all()),
                Remapped::Remapped(0x10000),
            ),
            ViewRegion::new(
                Access::new(0x2000, 0x1000, Rights::all()),
                Remapped::Remapped(0x12000),
            ),
        ];
        assert_eq!(view, expected);
    }

    // Okay now attempt to plug the hole.
    let err = engine.send(td0.clone(), child_td, plug, Remapped::Remapped(0x11000));
    assert!(err.is_err());

    // Let's revoke everything.
    engine.revoke(td0.clone(), child_td, 0).unwrap();

    // Check revoking makes all things good.
    let view = td0.borrow().view().unwrap();
    let expected = vec![ViewRegion::new(
        Access::new(0x0, 0x10000, Rights::all()),
        Remapped::Identity,
    )];
    assert_eq!(view, expected);
}
