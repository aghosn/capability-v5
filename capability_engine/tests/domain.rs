use capa_engine::capability::*;
use capa_engine::domain::*;
use capa_engine::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Rights, Status as MStatus,
};
use capa_engine::Engine;
use std::cell::RefCell;
use std::rc::Rc;

fn create_root_domain() -> Capability<Domain> {
    let policies = Policies::new(0b111111, MonitorAPI::all(), InterruptPolicy::default_all());
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
fn test_empty_root_domain() {
    let domain = create_root_domain();
    let display_output = format!("{}", domain);
    let expected_output = format!("td0 = Sealed domain()\n|cores: 0x3f\n|mon.api: 0x1fff\n|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0\n");
    assert_eq!(display_output, expected_output)
}

#[test]
fn test_root_domain_with_root_memory() {
    let mut domain = create_root_domain();
    let region = create_root();
    let reference = Rc::new(RefCell::new(region));
    domain.data.install(CapaWrapper::Region(reference));

    let display_output = format!("{}", domain);
    let expected_output = format!("td0 = Sealed domain(r0)\n|cores: 0x3f\n|mon.api: 0x1fff\n|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0\nr0 = Exclusive 0x0 0x10000 with RWX mapped Identity\n");
    assert_eq!(display_output, expected_output);
}

#[test]
fn test_unallowed_calls() {
    let (engine, td0, _r0, td0_r0) = setup_engine_with_root();

    let child_td = engine
        .create(
            td0.clone(),
            1,
            MonitorAPI::ATTEST,
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Let's seal the child directly.
    engine.seal(td0.clone(), child_td).unwrap();

    // Now try to send it something.
    let access = Access::new(0x0, 0x1000, Rights::all());
    let alias = engine.alias(td0.clone(), td0_r0, &access).unwrap();

    let res = engine.send(td0.clone(), child_td, alias, Remapped::Identity);
    assert!(res.is_err());

    engine.revoke(td0.clone(), child_td, 0).unwrap();

    // Now try to make the child do stuff while not sealed.
    let child_td = engine
        .create(
            td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    engine
        .send(td0.clone(), child_td, alias, Remapped::Identity)
        .unwrap();

    {
        let child = td0
            .borrow()
            .data
            .capabilities
            .get(&child_td)
            .unwrap()
            .as_domain()
            .unwrap();

        let access = Access::new(0x0, 0x1000, Rights::READ);
        let res = engine.alias(child.clone(), 1, &access);
        assert_eq!(res, Err(CapaError::DomainUnsealed));
    }

    engine.revoke(td0.clone(), child_td, 0).unwrap();

    // Okay last one.
    let child_td = engine
        .create(
            td0.clone(),
            1,
            MonitorAPI::CARVE,
            InterruptPolicy::default_none(),
        )
        .unwrap();

    let alias = engine.alias(td0.clone(), td0_r0, &access).unwrap();
    engine
        .send(td0.clone(), child_td, alias, Remapped::Identity)
        .unwrap();
    engine.seal(td0.clone(), child_td).unwrap();

    {
        let child = td0
            .borrow()
            .data
            .capabilities
            .get(&child_td)
            .unwrap()
            .as_domain()
            .unwrap();

        let res = engine.alias(child.clone(), 1, &Access::new(0x0, 0x1000, Rights::READ));
        assert_eq!(res, Err(CapaError::CallNotAllowed));

        let res = child.borrow().seal(1);
        assert!(res.is_err());
    }

    // Okay try to reseal the same domain.
    let res = engine.seal(td0.clone(), child_td);
    assert_eq!(res, Err(CapaError::DomainSealed));

    // Try to seal something wrong.
    let res = engine.seal(td0.clone(), td0_r0);
    assert_eq!(res, Err(CapaError::WrongCapaType));
    let res = td0.borrow().seal(td0_r0);
    assert_eq!(res, Err(CapaError::WrongCapaType));
}

#[test]
fn test_set_get() {
    let (engine, td0, _r0, _td0_r0) = setup_engine_with_root();

    // Create a child domain

    let child_td = engine
        .create(
            td0.clone(),
            1,
            MonitorAPI::all(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // First let's seal it and see if we read the right things.
    engine.seal(td0.clone(), child_td).unwrap();

    let cores = engine
        .get(td0.clone(), child_td, 0, FieldType::Cores, 0)
        .unwrap();
    assert_eq!(cores, 1);

    let api = engine
        .get(td0.clone(), child_td, 0, FieldType::Api, 0)
        .unwrap();
    assert_eq!(api, MonitorAPI::all().bits() as usize);

    for i in 0..NB_INTERRUPTS {
        let vis = engine
            .get(td0.clone(), child_td, 0, FieldType::InterruptVisibility, i)
            .unwrap();
        let read = engine
            .get(td0.clone(), child_td, 0, FieldType::InterruptRead, i)
            .unwrap();
        let write = engine
            .get(td0.clone(), child_td, 0, FieldType::InterruptWrite, i)
            .unwrap();
        assert_eq!(vis, 0);
        assert_eq!(read, !0);
        assert_eq!(write, !0);
    }

    // Now attempt to change policies.
    let res = engine.set(td0.clone(), child_td, 0, FieldType::Cores, 0, 0b11);
    assert_eq!(res, Err(CapaError::DomainSealed));
    let res = engine.set(td0.clone(), child_td, 0, FieldType::Api, 0, 0);
    assert_eq!(res, Err(CapaError::DomainSealed));
    for i in 0..NB_INTERRUPTS {
        let res = engine.set(
            td0.clone(),
            child_td,
            0,
            FieldType::InterruptVisibility,
            i,
            1,
        );
        assert_eq!(res, Err(CapaError::DomainSealed));
        let res = engine.set(td0.clone(), child_td, 0, FieldType::InterruptRead, i, 1);
        assert_eq!(res, Err(CapaError::DomainSealed));
        let res = engine.set(td0.clone(), child_td, 0, FieldType::InterruptWrite, i, 1);
        assert_eq!(res, Err(CapaError::DomainSealed));
    }

    // Revoke and now lets do sets.
    engine.revoke(td0.clone(), child_td, 0).unwrap();

    // Create the new one and play with its values.
    let child_td = engine
        .create(
            td0.clone(),
            1,
            MonitorAPI::empty(),
            InterruptPolicy::default_none(),
        )
        .unwrap();

    // Now attempt to change policies.
    engine
        .set(td0.clone(), child_td, 0, FieldType::Cores, 0, 0b11)
        .unwrap();
    engine
        .set(
            td0.clone(),
            child_td,
            0,
            FieldType::Api,
            0,
            MonitorAPI::all().bits() as usize,
        )
        .unwrap();
    for i in 0..NB_INTERRUPTS {
        engine
            .set(
                td0.clone(),
                child_td,
                0,
                FieldType::InterruptVisibility,
                i,
                VectorVisibility::all().bits() as usize,
            )
            .unwrap();
        engine
            .set(td0.clone(), child_td, 0, FieldType::InterruptRead, i, 0)
            .unwrap();
        engine
            .set(td0.clone(), child_td, 0, FieldType::InterruptWrite, i, 0)
            .unwrap();
    }

    // Try to set a field that's above the allowed range.
    let res = engine.set(
        td0.clone(),
        child_td,
        0,
        FieldType::InterruptVisibility,
        NB_INTERRUPTS + 2,
        555,
    );
    assert_eq!(res, Err(CapaError::InvalidField));
    // Same for get.
    let res = engine.get(
        td0.clone(),
        child_td,
        0,
        FieldType::InterruptVisibility,
        NB_INTERRUPTS + 2,
    );
    assert_eq!(res, Err(CapaError::InvalidField));

    // Let's try to see if we can overload the cores before sealing.
    // This should work, but then we will see if when we attempt to seal.
    engine
        .set(
            td0.clone(),
            child_td,
            0,
            FieldType::Cores,
            0,
            0b1111111111111111,
        )
        .unwrap();

    let res = engine.seal(td0.clone(), child_td);
    assert_eq!(res, Err(CapaError::InsufficientRights));

    engine
        .set(td0.clone(), child_td, 0, FieldType::Cores, 0, 0b11)
        .unwrap();
    engine.seal(td0.clone(), child_td).unwrap();
    engine.revoke(td0.clone(), child_td, 0).unwrap();
}
