use capa_engine::core::capability::*;
use capa_engine::core::domain::*;
use capa_engine::core::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Rights, Status as MStatus,
};
use capa_engine::server::engine::Engine;
use capa_engine::EngineInterface;
use std::cell::RefCell;
use std::rc::Rc;

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
    let engine = Engine::new(16);
    let root_region = create_root_region();

    let ref_mem = Rc::new(RefCell::new(root_region));
    let ref_region = engine
        .add_root_region(&engine.root.clone(), &ref_mem)
        .unwrap();
    let ref_td = engine.root.clone();
    (engine, ref_td, ref_mem, ref_region)
}

#[test]
fn test_engine_create_root_and_simple_child() {
    // Initial setup
    let (mut engine, ref_td, ref_mem, ref_region) = setup_engine_with_root();

    assert_eq!(Rc::strong_count(&ref_td), 2);
    assert_eq!(Rc::weak_count(&ref_td), 1);
    assert_eq!(Rc::strong_count(&ref_mem), 2);

    {
        // Create a child.
        let child_td = engine
            .create(
                &ref_td.clone(),
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
        engine
            .send(
                ref_td.clone(),
                child_td,
                ref_aliased,
                Remapped::Identity,
                Attributes::empty(),
            )
            .unwrap();
        engine
            .send(
                ref_td.clone(),
                child_td,
                ref_carved,
                Remapped::Identity,
                Attributes::empty(),
            )
            .unwrap();

        // Seal
        engine.seal(ref_td.clone(), child_td).unwrap();

        // Print the root domain.
        let display = format!("{}", ref_td.borrow());
        let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1,r2)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x0 0x2000 with RW_ for r1
| Carve at 0x2000 0x4000 with RWX for r2
r1 = Aliased 0x0 0x2000 with RW_ mapped Identity
r2 = Exclusive 0x2000 0x4000 with RWX mapped Identity
|indices: 1->r0 2->td1
"#;

        assert_eq!(display, expected);
        // Print the child domain.
        let child = ref_td
            .borrow()
            .data
            .capabilities
            .get(&child_td)
            .unwrap()
            .as_domain()
            .unwrap();
        let display = format!("{}", child.borrow());
        let expected = r#"td0 = Sealed domain(r0,r1)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Aliased 0x0 0x2000 with RW_ mapped Identity
r1 = Exclusive 0x2000 0x4000 with RWX mapped Identity
|indices: 1->r0 2->r1
"#;
        assert_eq!(display, expected);

        // Now hack the engine to make a new capability appear.
        let phantom = Rc::new(RefCell::new(Capability::<MemoryRegion>::new(
            MemoryRegion {
                kind: RegionKind::Carve,
                status: MStatus::Exclusive,
                access: Access::new(
                    0x15000,
                    0x20000,
                    Rights::READ | Rights::WRITE | Rights::EXECUTE,
                ),
                attributes: Attributes::NONE,
                remapped: Remapped::Identity,
            },
        )));
        let ref_phantom = child
            .borrow_mut()
            .data
            .install(CapaWrapper::Region(phantom));

        // Now do the attestation again, we should see a region that is not reported.
        let display = format!("{}", ref_td.borrow());
        let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1,r2,r3)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x0 0x2000 with RW_ for r1
| Carve at 0x2000 0x4000 with RWX for r2
r1 = Aliased 0x0 0x2000 with RW_ mapped Identity
r2 = Exclusive 0x2000 0x4000 with RWX mapped Identity
|indices: 1->r0 2->td1
"#;
        assert_eq!(display, expected);

        // Now display the children again.
        let display = format!("{}", child.borrow());
        let expected = r#"td0 = Sealed domain(r0,r1,r2)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Aliased 0x0 0x2000 with RW_ mapped Identity
r1 = Exclusive 0x2000 0x4000 with RWX mapped Identity
r2 = Exclusive 0x15000 0x35000 with RWX mapped Identity
|indices: 1->r0 2->r1 3->r2
"#;
        assert_eq!(display, expected);

        // Remove the phantom.
        _ = child.borrow_mut().data.remove(ref_phantom);

        // Now we can revoke, let's first revoke one capa, then revoke the domain.
        engine.revoke(ref_td.clone(), ref_region, 0).unwrap();

        let display = format!("{}", ref_td.borrow());
        let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x2000 0x4000 with RWX for r1
r1 = Exclusive 0x2000 0x4000 with RWX mapped Identity
|indices: 1->r0 2->td1
"#;
        assert_eq!(display, expected);

        let display = format!("{}", child.borrow());
        let expected = r#"td0 = Sealed domain(r0)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x2000 0x4000 with RWX mapped Identity
|indices: 2->r0
"#;
        assert_eq!(display, expected);

        engine.revoke(ref_td.clone(), child_td, 0).unwrap();
        let display = format!("{}", ref_td.borrow());
        let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
        assert_eq!(display, expected);
    }

    assert_eq!(Rc::strong_count(&ref_td), 2);
    assert_eq!(Rc::weak_count(&ref_td), 1);
    assert_eq!(Rc::strong_count(&ref_mem), 2);
}

#[test]
fn test_engine_nested_child_revoke_td() {
    // Initial setup
    let (mut engine, td0, r0, td0_r0) = setup_engine_with_root();
    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);
    // Main logic.
    let td0_td1 = {
        // Let td0 create td1.
        let td0_td1 = engine
            .create(
                &td0.clone(),
                0b111,
                MonitorAPI::all(),
                InterruptPolicy::default_all(),
            )
            .unwrap();

        // Let's do a carve and an alias and send it to td1.
        {
            let td0_r0_carve = engine
                .carve(
                    td0.clone(),
                    td0_r0,
                    &Access::new(0x0, 0x4000, Rights::all()),
                )
                .unwrap();
            let td0_r0_alias = engine
                .alias(
                    td0.clone(),
                    td0_r0,
                    &Access::new(0x5000, 0x1000, Rights::READ | Rights::WRITE),
                )
                .unwrap();
            engine
                .send(
                    td0.clone(),
                    td0_td1,
                    td0_r0_carve,
                    Remapped::Identity,
                    Attributes::empty(),
                )
                .unwrap();
            engine
                .send(
                    td0.clone(),
                    td0_td1,
                    td0_r0_alias,
                    Remapped::Identity,
                    Attributes::empty(),
                )
                .unwrap();
            // Finally seal the td.
            engine.seal(td0.clone(), td0_td1).unwrap();
        }

        // Now let's access td1 and create td2.
        {
            let td1 = &td0.borrow().children[0];
            let td1_td2 = engine
                .create(
                    &td1.clone(),
                    0b11,
                    MonitorAPI::encapsulated(),
                    InterruptPolicy::default_none(),
                )
                .unwrap();

            // Now create the regions and send them.
            let td1_carve = engine
                .carve(td1.clone(), 1, &Access::new(0x2000, 0x1000, Rights::all()))
                .unwrap();
            let td1_alias = engine
                .alias(
                    td1.clone(),
                    1,
                    &Access::new(0x3000, 0x1000, Rights::READ | Rights::WRITE),
                )
                .unwrap();
            engine
                .send(
                    td1.clone(),
                    td1_td2,
                    td1_carve,
                    Remapped::Identity,
                    Attributes::empty(),
                )
                .unwrap();
            engine
                .send(
                    td1.clone(),
                    td1_td2,
                    td1_alias,
                    Remapped::Identity,
                    Attributes::empty(),
                )
                .unwrap();
            engine.seal(td1.clone(), td1_td2).unwrap();
        }
        td0_td1
    };
    // Let's check everything is well-formed.
    {
        // Check td0.
        {
            let c_td0 = &td0.borrow();
            let display = format!("{}", c_td0);
            let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(td2,r1,r2)
|cores: 0x7
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x4000 with RWX for r1
| Alias at 0x5000 0x6000 with RW_ for r2
r1 = Exclusive 0x0 0x4000 with RWX mapped Identity
r2 = Aliased 0x5000 0x6000 with RW_ mapped Identity
|indices: 1->r0 2->td1
"#;
            assert_eq!(display, expected);
        }
        // Check td1
        {
            let c_td1 = &td0.borrow().children[0];
            let display = format!("{}", c_td1.borrow());
            let expected = r#"td0 = Sealed domain(td1,r0,r1)
|cores: 0x7
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r2,r3)
|cores: 0x3
|mon.api: 0xe0
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x4000 with RWX mapped Identity
| Carve at 0x2000 0x3000 with RWX for r2
| Alias at 0x3000 0x4000 with RW_ for r3
r1 = Aliased 0x5000 0x6000 with RW_ mapped Identity
r2 = Exclusive 0x2000 0x3000 with RWX mapped Identity
r3 = Aliased 0x3000 0x4000 with RW_ mapped Identity
|indices: 1->r0 2->r1 3->td1
"#;
            assert_eq!(display, expected);
        }
        // Check td2
        {
            let display = format!(
                "{}",
                &td0.borrow().children[0].borrow().children[0].borrow(),
            );
            let expected = r#"td0 = Sealed domain(r0,r1)
|cores: 0x3
|mon.api: 0xe0
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x2000 0x3000 with RWX mapped Identity
r1 = Aliased 0x3000 0x4000 with RW_ mapped Identity
|indices: 1->r0 2->r1
"#;
            assert_eq!(display, expected);
        }
        // Now we revoke td1 from td0.
        engine.revoke(td0.clone(), td0_td1, 0).unwrap();
        // Check td0
        {
            let c_td0 = &td0.borrow();
            let display = format!("{}", c_td0);
            let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
            assert_eq!(display, expected);

            // Now check the structures.
            assert_eq!(c_td0.children.len(), 0);
            assert_eq!(c_td0.data.capabilities.capabilities.len(), 1);

            let mem = c_td0
                .data
                .capabilities
                .get(&1)
                .unwrap()
                .as_region()
                .unwrap();
            assert_eq!(mem.borrow().children.len(), 0);
        }
    }

    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);
}

#[test]
fn test_engine_nested_revoke_r1() {
    // Initial setup
    let (mut engine, td0, r0, td0_r0) = setup_engine_with_root();
    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);
    // Main logic.
    let td0_td1 = {
        // Let td0 create td1.
        let td0_td1 = engine
            .create(
                &td0.clone(),
                0b111,
                MonitorAPI::all(),
                InterruptPolicy::default_all(),
            )
            .unwrap();

        // Let's do a carve and an alias and send it to td1.
        {
            let td0_r0_carve = engine
                .carve(
                    td0.clone(),
                    td0_r0,
                    &Access::new(0x0, 0x4000, Rights::all()),
                )
                .unwrap();
            let td0_r0_alias = engine
                .alias(
                    td0.clone(),
                    td0_r0,
                    &Access::new(0x5000, 0x1000, Rights::READ | Rights::WRITE),
                )
                .unwrap();
            engine
                .send(
                    td0.clone(),
                    td0_td1,
                    td0_r0_carve,
                    Remapped::Identity,
                    Attributes::empty(),
                )
                .unwrap();
            engine
                .send(
                    td0.clone(),
                    td0_td1,
                    td0_r0_alias,
                    Remapped::Identity,
                    Attributes::empty(),
                )
                .unwrap();
            // Finally seal the td.
            engine.seal(td0.clone(), td0_td1).unwrap();
        }

        // Now let's access td1 and create td2.
        {
            let td1 = &td0.borrow().children[0];
            let td1_td2 = engine
                .create(
                    &td1.clone(),
                    0b11,
                    MonitorAPI::encapsulated(),
                    InterruptPolicy::default_none(),
                )
                .unwrap();

            // Now create the regions and send them.
            let td1_carve = engine
                .carve(td1.clone(), 1, &Access::new(0x2000, 0x1000, Rights::all()))
                .unwrap();
            let td1_alias = engine
                .alias(
                    td1.clone(),
                    1,
                    &Access::new(0x3000, 0x1000, Rights::READ | Rights::WRITE),
                )
                .unwrap();
            engine
                .send(
                    td1.clone(),
                    td1_td2,
                    td1_carve,
                    Remapped::Identity,
                    Attributes::empty(),
                )
                .unwrap();
            engine
                .send(
                    td1.clone(),
                    td1_td2,
                    td1_alias,
                    Remapped::Identity,
                    Attributes::empty(),
                )
                .unwrap();
            engine.seal(td1.clone(), td1_td2).unwrap();
        }
        td0_td1
    };
    // Let's check everything is well-formed.
    {
        // Check td0.
        {
            let c_td0 = &td0.borrow();
            let display = format!("{}", c_td0);
            let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(td2,r1,r2)
|cores: 0x7
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x4000 with RWX for r1
| Alias at 0x5000 0x6000 with RW_ for r2
r1 = Exclusive 0x0 0x4000 with RWX mapped Identity
r2 = Aliased 0x5000 0x6000 with RW_ mapped Identity
|indices: 1->r0 2->td1
"#;
            assert_eq!(display, expected);
        }
        // Check td1
        {
            let c_td1 = &td0.borrow().children[0];
            let display = format!("{}", c_td1.borrow());
            let expected = r#"td0 = Sealed domain(td1,r0,r1)
|cores: 0x7
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r2,r3)
|cores: 0x3
|mon.api: 0xe0
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x4000 with RWX mapped Identity
| Carve at 0x2000 0x3000 with RWX for r2
| Alias at 0x3000 0x4000 with RW_ for r3
r1 = Aliased 0x5000 0x6000 with RW_ mapped Identity
r2 = Exclusive 0x2000 0x3000 with RWX mapped Identity
r3 = Aliased 0x3000 0x4000 with RW_ mapped Identity
|indices: 1->r0 2->r1 3->td1
"#;
            assert_eq!(display, expected);
        }
        // Check td2
        {
            let display = format!(
                "{}",
                &td0.borrow().children[0].borrow().children[0].borrow(),
            );
            let expected = r#"td0 = Sealed domain(r0,r1)
|cores: 0x3
|mon.api: 0xe0
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x2000 0x3000 with RWX mapped Identity
r1 = Aliased 0x3000 0x4000 with RW_ mapped Identity
|indices: 1->r0 2->r1
"#;
            assert_eq!(display, expected);
        }
        // Now we revoke td1's r1 from td0.
        engine.revoke(td0.clone(), td0_r0, 0).unwrap();
        // Check td0
        {
            let c_td0 = &td0.borrow();
            let display = format!("{}", c_td0);
            let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(td2,r1)
|cores: 0x7
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x5000 0x6000 with RW_ for r1
r1 = Aliased 0x5000 0x6000 with RW_ mapped Identity
|indices: 1->r0 2->td1
"#;
            assert_eq!(display, expected);

            // Now check the structures.
            assert_eq!(c_td0.children.len(), 1);
            assert_eq!(c_td0.data.capabilities.capabilities.len(), 2);

            let mem = c_td0
                .data
                .capabilities
                .get(&td0_r0)
                .unwrap()
                .as_region()
                .unwrap();
            assert_eq!(mem.borrow().children.len(), 1);
        }
        // Check td1
        {
            let c_td1 = &td0.borrow().children[0];
            let display = format!("{}", c_td1.borrow());
            let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0x7
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain()
|cores: 0x3
|mon.api: 0xe0
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Aliased 0x5000 0x6000 with RW_ mapped Identity
|indices: 2->r0 3->td1
"#;
            assert_eq!(display, expected);

            // Now check the structures.
            assert_eq!(c_td1.borrow().children.len(), 1);
            assert_eq!(c_td1.borrow().data.capabilities.capabilities.len(), 2);

            let mem = c_td1
                .borrow()
                .data
                .capabilities
                .get(&2)
                .unwrap()
                .as_region()
                .unwrap();
            assert_eq!(mem.borrow().children.len(), 0);
        }
        engine.revoke(td0.clone(), td0_td1, 0).unwrap();
    }

    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);
}

#[test]
fn test_engine_two_children_revoke_aliased_twice() {
    // Initial setup
    let (mut engine, td0, r0, td0_r0) = setup_engine_with_root();
    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    {
        // Let td0 create td1.
        let td0_td1 = engine
            .create(
                &td0.clone(),
                0b111,
                MonitorAPI::all(),
                InterruptPolicy::default_all(),
            )
            .unwrap();
        // Let td0 create td2
        let td0_td2 = engine
            .create(
                &td0.clone(),
                0b111,
                MonitorAPI::all(),
                InterruptPolicy::default_all(),
            )
            .unwrap();

        // Carve a region.
        let td0_carve = engine
            .carve(
                td0.clone(),
                td0_r0,
                &Access::new(0x0, 0x2000, Rights::all()),
            )
            .unwrap();

        // Do two aliases.
        let td0_alias_td1 = engine
            .alias(
                td0.clone(),
                td0_carve,
                &Access::new(0x0, 0x2000, Rights::all()),
            )
            .unwrap();
        let td0_alias_td2 = engine
            .alias(
                td0.clone(),
                td0_carve,
                &Access::new(0x0, 0x1000, Rights::all()),
            )
            .unwrap();
        // Send the capas.
        engine
            .send(
                td0.clone(),
                td0_td1,
                td0_alias_td1,
                Remapped::Identity,
                Attributes::empty(),
            )
            .unwrap();
        engine
            .send(
                td0.clone(),
                td0_td2,
                td0_alias_td2,
                Remapped::Identity,
                Attributes::empty(),
            )
            .unwrap();

        // Seal the domains.
        engine.seal(td0.clone(), td0_td1).unwrap();
        engine.seal(td0.clone(), td0_td2).unwrap();

        // Now check the output.
        let display = format!("{}", td0.borrow());
        let expected = r#"td0 = Sealed domain(td1,td2,r0,r1)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r2)
|cores: 0x7
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td2 = Sealed domain(r3)
|cores: 0x7
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x2000 with RWX for r1
r1 = Exclusive 0x0 0x2000 with RWX mapped Identity
| Alias at 0x0 0x2000 with RWX for r2
| Alias at 0x0 0x1000 with RWX for r3
r2 = Aliased 0x0 0x2000 with RWX mapped Identity
r3 = Aliased 0x0 0x1000 with RWX mapped Identity
|indices: 1->r0 2->td1 3->td2 4->r1
"#;
        assert_eq!(display, expected);

        // Now revoke the carve.
        engine.revoke(td0.clone(), td0_r0, 0).unwrap();

        // Now make sure the display is correct.
        let display = format!("{}", td0.borrow());
        let expected = r#"td0 = Sealed domain(td1,td2,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain()
|cores: 0x7
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td2 = Sealed domain()
|cores: 0x7
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0 2->td1 3->td2
"#;
        assert_eq!(display, expected);

        // Now revoke both domains.
        engine.revoke(td0.clone(), td0_td1, 0).unwrap();
        engine.revoke(td0.clone(), td0_td2, 0).unwrap();
    }
    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);
}

#[test]
fn test_engine_nested_domains_three_branches() {
    // Initial setup
    let (mut engine, td0, r0, _) = setup_engine_with_root();
    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let mut create_three_domains = |capa_me: &CapaRef<Domain>| -> Vec<LocalCapa> {
        let mut handles: Vec<LocalCapa> = Vec::new();
        for _i in 0..3 {
            let local = engine
                .create(
                    &capa_me.clone(),
                    0x1,
                    MonitorAPI::all(),
                    InterruptPolicy::default_all(),
                )
                .unwrap();
            handles.push(local);
            engine.seal(capa_me.clone(), local).unwrap();
        }
        handles
    };

    {
        let handles_td0 = create_three_domains(&td0);
        for child in &td0.borrow().children {
            let _ = create_three_domains(&child);
            for grandchild in &child.borrow().children {
                let _ = create_three_domains(&grandchild);
            }
        }

        // Now make sure everyone has three children.
        let display = format!("{}", td0.borrow());
        let expected = r#"td0 = Sealed domain(td1,td2,td3,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(td4,td5,td6)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td2 = Sealed domain(td7,td8,td9)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td3 = Sealed domain(td10,td11,td12)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0 2->td1 3->td2 4->td3
"#;
        assert_eq!(display, expected);

        // Now attest each of the children.
        for i in &handles_td0 {
            let child = td0
                .borrow()
                .data
                .capabilities
                .get(i)
                .unwrap()
                .as_domain()
                .unwrap();
            let display = format!("{}", child.borrow());
            let expected = r#"td0 = Sealed domain(td1,td2,td3)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(td4,td5,td6)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td2 = Sealed domain(td7,td8,td9)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td3 = Sealed domain(td10,td11,td12)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
|indices: 1->td1 2->td2 3->td3
"#;
            assert_eq!(display, expected);
        }

        // Now revoke them
        for i in &handles_td0 {
            engine.revoke(td0.clone(), *i, 0).unwrap();
        }

        // Display td0
        let display = format!("{}", td0.borrow());
        let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
        assert_eq!(display, expected);
    }
    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);
}

#[test]
fn test_engine_reclaim_from_grand_child() {
    // Initial setup
    let (mut engine, td0, r0, td0_r0) = setup_engine_with_root();
    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    let carve = engine
        .carve(
            td0.clone(),
            td0_r0,
            &Access::new(0x0, 0x1000, Rights::all()),
        )
        .unwrap();

    {
        let mut current: CapaRef<Domain> = td0.clone();
        let mut to_send: LocalCapa = carve;
        for _i in 0..5 {
            let child = engine
                .create(
                    &current.clone(),
                    0b1,
                    MonitorAPI::all(),
                    InterruptPolicy::default_all(),
                )
                .unwrap();
            engine.seal(current.clone(), child).unwrap();
            engine
                .send(
                    current.clone(),
                    child,
                    to_send,
                    Remapped::Identity,
                    Attributes::empty(),
                )
                .unwrap();
            // Update to point to the child.
            let child_ref = current
                .borrow()
                .data
                .capabilities
                .get(&child)
                .unwrap()
                .as_domain()
                .unwrap();
            current = child_ref;
            to_send = 1;
        }

        // Now check the child that has the region.
        let display = format!("{}", current.borrow());
        let expected = r#"td0 = Sealed domain(r0)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x1000 with RWX mapped Identity
|indices: 1->r0
"#;
        assert_eq!(display, expected);

        // Now revoke from td0.
        engine.revoke(td0.clone(), td0_r0, 0).unwrap();

        let display = format!("{}", td0.borrow());
        let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(td2)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0 3->td1
"#;
        assert_eq!(display, expected);

        // Now revoke the domains in cascade.
        engine.revoke(td0.clone(), 3, 0).unwrap();

        // Check it worked.
        let display = format!("{}", td0.borrow());
        let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
        assert_eq!(display, expected);
    }
    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);
}

#[test]
fn test_engine_policies_core_fail() {
    // Initial setup
    let (mut engine, td0, r0, _td0_r0) = setup_engine_with_root();
    assert_eq!(Rc::strong_count(&td0), 2);
    assert_eq!(Rc::weak_count(&td0), 1);
    assert_eq!(Rc::strong_count(&r0), 2);

    // Let td0 create a domain and that domain try to gain more writes.
    {
        let mut api_without_send_rcv = MonitorAPI::all();
        api_without_send_rcv.remove(MonitorAPI::SEND | MonitorAPI::RECEIVE);
        let td0_td1 = engine
            .create(
                &td0.clone(),
                0b1,
                api_without_send_rcv,
                InterruptPolicy::default_none(),
            )
            .unwrap();
        engine.seal(td0.clone(), td0_td1).unwrap();

        // Now let the domain try to create a new one with more cores.
        let td1 = td0
            .borrow()
            .data
            .capabilities
            .get(&td0_td1)
            .unwrap()
            .as_domain()
            .unwrap();

        let td2_err = engine.create(
            &td1.clone(),
            0x2,
            MonitorAPI::all(),
            InterruptPolicy::default_all(),
        );
        assert!(td2_err.is_err());

        // Now let's try the wrong interrupt policies.
        let td1_td2 = engine
            .create(
                &td1.clone(),
                0b1,
                api_without_send_rcv,
                InterruptPolicy::default_all(),
            )
            .unwrap();

        assert!(engine.seal(td1.clone(), td1_td2).is_err());

        // Now let's try the wrong api policies.
        engine.revoke(td1.clone(), td1_td2, 0).unwrap();
        let td1_td2 = engine
            .create(
                &td1.clone(),
                0b1,
                MonitorAPI::all(),
                InterruptPolicy::default_none(),
            )
            .unwrap();

        assert!(engine.seal(td1.clone(), td1_td2).is_err());
    }
}

#[test]
fn test_engine_alias_then_carve_root() {
    // Initial setup
    let (mut engine, td0, _r0, td0_r0) = setup_engine_with_root();

    let access = Access::new(0x0, 0x1000, Rights::all());
    let _alias = engine.alias(td0.clone(), td0_r0, &access).unwrap();
    let err = engine.carve(td0.clone(), td0_r0, &access);
    assert!(err.is_err());

    // Try to alias it a second time.
    let _alias = engine.alias(td0.clone(), td0_r0, &access).unwrap();

    // Do the display.
    let display = format!("{}", td0.borrow());
    let expected = r#"td0 = Sealed domain(r0,r1,r2)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x0 0x1000 with RWX for r1
| Alias at 0x0 0x1000 with RWX for r2
r1 = Aliased 0x0 0x1000 with RWX mapped Identity
r2 = Aliased 0x0 0x1000 with RWX mapped Identity
|indices: 1->r0 2->r1 3->r2
"#;
    assert_eq!(display, expected);
}

#[test]
fn test_engine_alias_carve_root() {
    // Initial setup
    let (mut engine, td0, _r0, td0_r0) = setup_engine_with_root();

    let access = Access::new(0x0, 0x1000, Rights::all());
    let carve = engine.carve(td0.clone(), td0_r0, &access).unwrap();
    let err = engine.alias(td0.clone(), td0_r0, &access);
    assert!(err.is_err());

    // Try to alias it a second time.
    let carve2 = engine.carve(td0.clone(), td0_r0, &access);
    assert!(carve2.is_err());

    // Carve the carve.
    engine.carve(td0.clone(), carve, &access).unwrap();

    // Do the display.
    let display = format!("{}", td0.borrow());
    let expected = r#"td0 = Sealed domain(r0,r1,r2)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x1000 with RWX for r1
r1 = Exclusive 0x0 0x1000 with RWX mapped Identity
| Carve at 0x0 0x1000 with RWX for r2
r2 = Exclusive 0x0 0x1000 with RWX mapped Identity
|indices: 1->r0 2->r1 3->r2
"#;
    assert_eq!(display, expected);
}
