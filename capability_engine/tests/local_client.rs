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
