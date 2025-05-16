use capa_engine::client::engine::ClientInterface;
use capa_engine::client::engine::Engine;
use capa_engine::client::local_client::LocalClient;
use capa_engine::core::capability::*;
use capa_engine::core::domain::*;
use capa_engine::core::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Rights, Status as MStatus,
};
use capa_engine::server::engine::Engine as SEngine;
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
