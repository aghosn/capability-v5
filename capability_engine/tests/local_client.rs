use capa_engine::client::engine::ClientInterface;
use capa_engine::client::engine::Engine;
use capa_engine::client::local_client::LocalClient;
use capa_engine::core::capability::*;
use capa_engine::core::domain::*;
use capa_engine::core::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Rights, Status as MStatus,
};
use capa_engine::server::engine::Engine as SEngine;
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

fn setup() -> Engine<LocalClient> {
    let local = LocalClient::init();
    let root_domain = create_root_domain();
    let ref_root = Rc::new(RefCell::new(root_domain));
    let engine = Engine::<LocalClient> {
        platform: local,
        current: ref_root,
    };

    let root_region = create_root_region();
    let ref_mem = Rc::new(RefCell::new(root_region));
    let _ = engine
        .platform
        .server
        .add_root_region(&engine.platform.current.clone(), &ref_mem)
        .unwrap();
    // Cheat to add a root region for client engine.
    {
        let root_reg = create_root_region();
        let ref_mem = Rc::new(RefCell::new(root_reg));
        let sengine = SEngine {};
        let _ = sengine
            .add_root_region(&engine.current.clone(), &ref_mem)
            .unwrap();
    }
    engine
}

#[test]
fn test_client_create() {
    let mut client = setup();

    // Check that the initial attesttion is correct.
    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
    assert_eq!(attestation, expected);

    // Create and attest again.
    let child_td = client
        .r_create(0x1, MonitorAPI::all(), InterruptPolicy::default_none())
        .unwrap();
    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Unsealed domain()
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0 2->td1
"#;
    assert_eq!(attestation, expected);

    // Seal it and attest again.
    client.r_seal(&child_td).unwrap();
    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain()
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0 2->td1
"#;
    assert_eq!(attestation, expected);
}

#[test]
fn test_client_alias() {
    let mut client = setup();

    let r0 = client.find_region(|_x| true).unwrap();
    let r1 = client
        .r_alias(
            &r0.clone(),
            0x0,
            0x1000,
            (Rights::READ | Rights::WRITE).bits(),
        )
        .unwrap();

    // Check we have the right attestations.
    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(r0,r1)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x0 0x1000 with RW_ for r1
r1 = Aliased 0x0 0x1000 with RW_ mapped Identity
|indices: 1->r0 2->r1
"#;
    assert_eq!(attestation, expected);

    // Check the local state too.
    let attestation = format!("{}", client.current.borrow());
    assert_eq!(attestation, expected);

    // Check r1 is correct too.
    let display = format!("{}", r1.borrow());
    let expected = "Aliased 0x0 0x1000 with RW_ mapped Identity";
    assert_eq!(display, expected)
}

#[test]
fn test_client_carve() {
    let mut client = setup();

    // We have only one region.
    let r0 = client.find_region(|_x| true).unwrap();
    let r1 = client
        .r_carve(
            &r0.clone(),
            0x0,
            0x1000,
            (Rights::READ | Rights::WRITE).bits(),
        )
        .unwrap();

    // Check we have the right attestations.
    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(r0,r1)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x1000 with RW_ for r1
r1 = Exclusive 0x0 0x1000 with RW_ mapped Identity
|indices: 1->r0 2->r1
"#;
    assert_eq!(attestation, expected);

    // Check the local state too.
    let attestation = format!("{}", client.current.borrow());
    assert_eq!(attestation, expected);

    // Check r1 is correct too.
    let display = format!("{}", r1.borrow());
    let expected = "Exclusive 0x0 0x1000 with RW_ mapped Identity";
    assert_eq!(display, expected)
}

#[test]
fn test_client_child_alias_carve() {
    let mut client = setup();

    // We have only one region.
    let r0 = client.find_region(|_x| true).unwrap();
    let r1 = client
        .r_carve(&r0.clone(), 0x0, 0x1000, Rights::all().bits())
        .unwrap();

    let r2 = client
        .r_alias(
            &r0.clone(),
            0x1000,
            0x1000,
            (Rights::READ | Rights::WRITE).bits(),
        )
        .unwrap();

    let td1 = client
        .r_create(0x1, MonitorAPI::all(), InterruptPolicy::default_none())
        .unwrap();

    client
        .r_send(&td1.clone(), &r1, Remapped::Identity)
        .unwrap();
    client
        .r_send(&td1.clone(), &r2, Remapped::Identity)
        .unwrap();

    client.r_seal(&td1.clone()).unwrap();

    // Check we have the right attestations.
    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1,r2)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x1000 with RWX for r1
| Alias at 0x1000 0x2000 with RW_ for r2
r1 = Exclusive 0x0 0x1000 with RWX mapped Identity
r2 = Aliased 0x1000 0x2000 with RW_ mapped Identity
|indices: 1->r0 4->td1
"#;
    assert_eq!(attestation, expected);

    // Check the local state too.
    let attestation = format!("{}", client.current.borrow());
    assert_eq!(attestation, expected);

    // Try the revoke.
    client.r_revoke_child(&td1.clone()).unwrap();

    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
    assert_eq!(attestation, expected);
    // Check the local state too.
    let attestation = format!("{}", client.current.borrow());
    assert_eq!(attestation, expected);
}

#[test]
fn test_client_multiple_children() {
    let mut client = setup();

    let r0 = client.find_region(|_| true).unwrap();
    let r1 = client
        .r_carve(&r0.clone(), 0x0, 0x1000, Rights::all().bits())
        .unwrap();
    let r2 = client
        .r_alias(
            &r0.clone(),
            0x1000,
            0x1000,
            (Rights::READ | Rights::WRITE).bits(),
        )
        .unwrap();
    let r3 = client
        .r_alias(
            &r0.clone(),
            0x1000,
            0x1000,
            (Rights::READ | Rights::WRITE).bits(),
        )
        .unwrap();
    let r4 = client
        .r_carve(&r0.clone(), 0x2000, 0x1000, Rights::all().bits())
        .unwrap();

    let td1 = client
        .r_create(0x1, MonitorAPI::all(), InterruptPolicy::default_none())
        .unwrap();
    let td2 = client
        .r_create(0x2, MonitorAPI::all(), InterruptPolicy::default_none())
        .unwrap();
    client
        .r_send(&td1.clone(), &r1, Remapped::Identity)
        .unwrap();
    client
        .r_send(&td1.clone(), &r2, Remapped::Identity)
        .unwrap();
    client.r_seal(&td1.clone()).unwrap();

    client
        .r_send(&td2.clone(), &r3, Remapped::Identity)
        .unwrap();
    client
        .r_send(&td2.clone(), &r4, Remapped::Identity)
        .unwrap();
    client.r_seal(&td2.clone()).unwrap();

    // Double children.
    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(td1,td2,r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1,r2)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
td2 = Sealed domain(r3,r4)
|cores: 0x2
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x1000 with RWX for r1
| Alias at 0x1000 0x2000 with RW_ for r2
| Alias at 0x1000 0x2000 with RW_ for r3
| Carve at 0x2000 0x3000 with RWX for r4
r1 = Exclusive 0x0 0x1000 with RWX mapped Identity
r2 = Aliased 0x1000 0x2000 with RW_ mapped Identity
r3 = Aliased 0x1000 0x2000 with RW_ mapped Identity
r4 = Exclusive 0x2000 0x3000 with RWX mapped Identity
|indices: 1->r0 6->td1 7->td2
"#;
    assert_eq!(attestation, expected);
    // Check the local state now.
    let attestation = format!("{}", client.current.borrow());
    assert_eq!(attestation, expected);

    // Now do something weird.
    let r5 = client
        .r_alias(&r0.clone(), 0x5000, 0x1000, Rights::all().bits())
        .unwrap();
    let r6 = client
        .r_alias(&r5.clone(), 0x5000, 0x1000, Rights::all().bits())
        .unwrap();

    client
        .r_send(&td2.clone(), &r5, Remapped::Identity)
        .unwrap();
    client
        .r_send(&td1.clone(), &r6, Remapped::Identity)
        .unwrap();

    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(td1,td2,r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1,r2,r6)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
td2 = Sealed domain(r3,r4,r5)
|cores: 0x2
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x1000 with RWX for r1
| Alias at 0x1000 0x2000 with RW_ for r2
| Alias at 0x1000 0x2000 with RW_ for r3
| Carve at 0x2000 0x3000 with RWX for r4
| Alias at 0x5000 0x6000 with RWX for r5
r1 = Exclusive 0x0 0x1000 with RWX mapped Identity
r2 = Aliased 0x1000 0x2000 with RW_ mapped Identity
r3 = Aliased 0x1000 0x2000 with RW_ mapped Identity
r4 = Exclusive 0x2000 0x3000 with RWX mapped Identity
r5 = Aliased 0x5000 0x6000 with RWX mapped Identity
|indices: 1->r0 6->td1 7->td2
"#;
    assert_eq!(attestation, expected);

    // Check the local state.
    let attestation = format!("{}", client.current.borrow());
    assert_eq!(attestation, expected);

    // Now revoke the r5 child.
    client.r_revoke_region(&r5).unwrap();
    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(td1,td2,r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1,r2)
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
td2 = Sealed domain(r3,r4)
|cores: 0x2
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x1000 with RWX for r1
| Alias at 0x1000 0x2000 with RW_ for r2
| Alias at 0x1000 0x2000 with RW_ for r3
| Carve at 0x2000 0x3000 with RWX for r4
r1 = Exclusive 0x0 0x1000 with RWX mapped Identity
r2 = Aliased 0x1000 0x2000 with RW_ mapped Identity
r3 = Aliased 0x1000 0x2000 with RW_ mapped Identity
r4 = Exclusive 0x2000 0x3000 with RWX mapped Identity
|indices: 1->r0 6->td1 7->td2
"#;
    assert_eq!(attestation, expected);
    // Check locally
    let attestation = format!("{}", client.current.borrow());
    assert_eq!(attestation, expected);

    // Now revoke everything.
    client.r_revoke_child(&td2).unwrap();
    client.r_revoke_child(&td1).unwrap();

    let attestation = client.r_attest(None).unwrap();
    let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
    assert_eq!(attestation, expected);
    // Check the local state.
    let attestation = format!("{}", client.current.borrow());
    assert_eq!(attestation, expected);
}

#[test]
fn test_client_exercise_set_get() {
    let mut client = setup();

    let td1 = client
        .r_create(0x1, MonitorAPI::all(), InterruptPolicy::default_none())
        .unwrap();

    // Change cores.
    client
        .r_set(&td1.clone(), 0, FieldType::Cores, 0, 0x22)
        .unwrap();
    // Get it and check.
    let v = client.r_get(&td1.clone(), 0, FieldType::Cores, 0).unwrap();
    assert_eq!(v, 0x22);

    // Check local and remote attestation.
    let attestation = format!("{}", td1.borrow());
    let expected = r#"td0 = Unsealed domain()
|cores: 0x22
|mon.api: 0x1fff
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
"#;
    assert_eq!(attestation, expected);
    let attestation = client.r_attest(Some(&td1.clone())).unwrap();
    assert_eq!(attestation, expected);

    // Change the monitor API.
    client
        .r_set(
            &td1.clone(),
            0,
            FieldType::Api,
            0,
            MonitorAPI::RECEIVE.bits() as u64,
        )
        .unwrap();
    // Get it and check.
    let v = client.r_get(&td1.clone(), 0, FieldType::Api, 0).unwrap();
    assert_eq!(v, MonitorAPI::RECEIVE.bits() as u64);

    // Check local and remote attestation.
    let attestation = format!("{}", td1.borrow());
    let expected = r#"td0 = Unsealed domain()
|cores: 0x22
|mon.api: 0x1000
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
"#;
    assert_eq!(attestation, expected);
    let attestation = client.r_attest(Some(&td1.clone())).unwrap();
    assert_eq!(attestation, expected);

    // Now go through the vectors.
    for i in 0..NB_INTERRUPTS {
        client
            .r_set(
                &td1.clone(),
                0,
                FieldType::InterruptVisibility,
                i as u64,
                VectorVisibility::ALLOWED.bits() as u64,
            )
            .unwrap();
        client
            .r_set(
                &td1.clone(),
                0,
                FieldType::InterruptRead,
                i as u64,
                i as u64,
            )
            .unwrap();
        client
            .r_set(
                &td1.clone(),
                0,
                FieldType::InterruptWrite,
                i as u64,
                i as u64,
            )
            .unwrap();
        // Now do the gets.
        let vis = client
            .r_get(&td1.clone(), 0, FieldType::InterruptVisibility, i as u64)
            .unwrap();
        let read = client
            .r_get(&td1.clone(), 0, FieldType::InterruptRead, i as u64)
            .unwrap();
        let write = client
            .r_get(&td1.clone(), 0, FieldType::InterruptWrite, i as u64)
            .unwrap();
        assert_eq!(vis, VectorVisibility::ALLOWED.bits() as u64);
        assert_eq!(read, i as u64);
        assert_eq!(write, i as u64);
    }
}

#[test]
fn test_client_100_children() {
    let mut client = setup();

    let r0 = client.find_region(|_x| true).unwrap();
    for _i in 0..100 {
        let child = client
            .r_create(0x1, MonitorAPI::empty(), InterruptPolicy::default_none())
            .unwrap();
        let r = client
            .r_alias(&r0.clone(), 0x2000, 0x1000, Rights::all().bits())
            .unwrap();
        client
            .r_send(&child.clone(), &r, Remapped::Identity)
            .unwrap();
        client.r_seal(&child).unwrap();
    }

    // Compare the two attestations.
    let local = format!("{}", client.current.borrow());
    let remote = client.r_attest(None).unwrap();
    assert_eq!(local, remote);
    // Check the first line of the attestation.
    {
        assert_eq!(*local
            .split("\n")
            .collect::<Vec<_>>()
            .get(0)
            .unwrap(), "td0 = Sealed domain(td1,td2,td3,td4,td5,td6,td7,td8,td9,td10,td11,td12,td13,td14,td15,td16,td17,td18,td19,td20,td21,td22,td23,td24,td25,td26,td27,td28,td29,td30,td31,td32,td33,td34,td35,td36,td37,td38,td39,td40,td41,td42,td43,td44,td45,td46,td47,td48,td49,td50,td51,td52,td53,td54,td55,td56,td57,td58,td59,td60,td61,td62,td63,td64,td65,td66,td67,td68,td69,td70,td71,td72,td73,td74,td75,td76,td77,td78,td79,td80,td81,td82,td83,td84,td85,td86,td87,td88,td89,td90,td91,td92,td93,td94,td95,td96,td97,td98,td99,td100,r0)");
    }

    // Now use find_child to loop and kill all the kids.
    let mut child = client.find_child(|_x| true);
    while child.is_some() {
        let c = child.unwrap();
        // Enumerate the child.
        let handle = c.borrow().owned.handle;
        let enumerate = client.enumerate(client.current.clone(), handle).unwrap();
        let expected = r#"td0 = Sealed domain(r0)
|cores: 0x1
|mon.api: 0x0
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Aliased 0x2000 0x3000 with RWX mapped Identity
|indices: 1->r0
"#;
        assert_eq!(enumerate, expected);
        // Do a wrong enumerate.
        let err = client.enumerate(client.current.clone(), 2000);
        assert!(err.is_err());

        client.r_revoke_child(&c).unwrap();
        child = client.find_child(|_x| true);
    }

    // Attest everything is good.
    let attestation = format!("{}", client.current.borrow());
    let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffffffffffffffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
    assert_eq!(attestation, expected);

    let attestation = client.r_attest(None).unwrap();
    assert_eq!(attestation, expected);
}
