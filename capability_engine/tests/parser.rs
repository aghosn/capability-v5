use capa_engine::core::capability::*;
use capa_engine::core::domain::*;
use capa_engine::core::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Rights, Status as MStatus,
};
use capa_engine::core::parser::Parser;
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
fn test_parse_simple_td0() {
    // Initial setup
    let (_engine, td0, _r0, _td0_r0) = setup_engine_with_root();

    let display = format!("{}", td0.borrow());
    let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
    assert_eq!(display, expected);

    // Now parse the attestation.
    let mut parser = Parser::new();
    parser.parse_attestation(display).unwrap();

    // Now print td0 from the parser
    let reconstructed_td0 = parser.domains.get("td0").unwrap();
    let display = format!("{}", reconstructed_td0.borrow());
    assert_eq!(display, expected);
}

#[test]
fn test_parse_with_alias() {
    // Initial setup
    let (mut engine, td0, _r0, td0_r0) = setup_engine_with_root();

    // Let's create some regions.
    let alias_access = Access::new(0x0, 0x3000, Rights::all());

    let _alias = engine.alias(td0.clone(), td0_r0, &alias_access).unwrap();

    let display = format!("{}", td0.borrow());
    let expected = r#"td0 = Sealed domain(r0,r1)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x0 0x3000 with RWX for r1
r1 = Aliased 0x0 0x3000 with RWX mapped Identity
|indices: 1->r0 2->r1
"#;
    assert_eq!(display, expected);
    let mut parser = Parser::new();
    parser.parse_attestation(display).unwrap();

    let td0_recon = parser.domains.get("td0").unwrap();
    let display = format!("{}", td0_recon.borrow());
    assert_eq!(display, expected);

    // Do some reconstruction checks.
    let r1 = parser.regions.get("r1").unwrap();
    assert_eq!(r1.borrow().data.kind, RegionKind::Alias);
    assert_eq!(r1.borrow().data.status, MStatus::Aliased);
    assert_eq!(r1.borrow().owned.handle, 2);
}

#[test]
fn test_parse_with_carve() {
    // Initial setup
    let (mut engine, td0, _r0, td0_r0) = setup_engine_with_root();

    // Let's create some regions.
    let carve_access = Access::new(0x0, 0x3000, Rights::all());

    let _carve = engine.carve(td0.clone(), td0_r0, &carve_access).unwrap();

    let display = format!("{}", td0.borrow());
    let expected = r#"td0 = Sealed domain(r0,r1)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x0 0x3000 with RWX for r1
r1 = Exclusive 0x0 0x3000 with RWX mapped Identity
|indices: 1->r0 2->r1
"#;
    assert_eq!(display, expected);
    let mut parser = Parser::new();
    parser.parse_attestation(display).unwrap();

    let td0_recon = parser.domains.get("td0").unwrap();
    let display = format!("{}", td0_recon.borrow());
    assert_eq!(display, expected);

    // Do some reconstruction checks.
    let r1 = parser.regions.get("r1").unwrap();
    assert_eq!(r1.borrow().data.kind, RegionKind::Carve);
    assert_eq!(r1.borrow().data.status, MStatus::Exclusive);
    assert_eq!(r1.borrow().owned.handle, 2);
}

#[test]
fn test_parse_with_td1() {
    // Initial setup
    let (mut engine, td0, _r0, _td0_r0) = setup_engine_with_root();

    // Let's create a child domain.
    let td1 = engine
        .create(
            &td0.clone(),
            0b1,
            MonitorAPI::all(),
            InterruptPolicy::default_all(),
        )
        .unwrap();

    let display = format!("{}", td0.borrow());
    let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Unsealed domain()
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0 2->td1
"#;
    assert_eq!(display, expected);
    let mut parser = Parser::new();
    parser.parse_attestation(display).unwrap();

    let td0_recon = parser.domains.get("td0").unwrap();
    let display = format!("{}", td0_recon.borrow());
    assert_eq!(display, expected);

    // Do some reconstruction checks.
    let r1 = parser.domains.get("td1").unwrap();
    assert_eq!(r1.borrow().data.status, Status::Unsealed);
    assert_eq!(r1.borrow().owned.handle, 2);

    // Now seal it.
    engine.seal(td0.clone(), td1).unwrap();
    let display = format!("{}", td0.borrow());
    let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain()
|cores: 0x1
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0 2->td1
"#;
    assert_eq!(display, expected);
    assert_eq!(display, expected);
    let mut parser = Parser::new();
    parser.parse_attestation(display).unwrap();

    let td0_recon = parser.domains.get("td0").unwrap();
    let display = format!("{}", td0_recon.borrow());
    assert_eq!(display, expected);
    // Do some reconstruction checks.
    let r1 = parser.domains.get("td1").unwrap();
    assert_eq!(r1.borrow().data.status, Status::Sealed);
    assert_eq!(r1.borrow().owned.handle, 2);
}

#[test]
fn test_parse_with_td1_and_region() {
    // Initial setup
    let (mut engine, td0, _r0, td0_r0) = setup_engine_with_root();

    let access = Access::new(0x1000, 0x2000, Rights::all());
    let carved = engine.carve(td0.clone(), td0_r0, &access).unwrap();

    // Create a child domain.
    let mut ipolicy = InterruptPolicy::default_none();
    ipolicy.vectors[3] = VectorPolicy {
        visibility: VectorVisibility::empty(),
        read_set: 0,
        write_set: 0,
    };
    let td1 = engine
        .create(&td0.clone(), 0b1, MonitorAPI::empty(), ipolicy)
        .unwrap();
    engine
        .send(
            td0.clone(),
            td1,
            carved,
            Remapped::Remapped(0x0),
            Attributes::empty(),
        )
        .unwrap();
    engine.seal(td0.clone(), td1).unwrap();

    // Check the display
    let display = format!("{}", td0.borrow());
    let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1)
|cores: 0x1
|mon.api: 0x0
|vec0-2: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
|vec3: NOT REPORTED, r: 0x0, w: 0x0
|vec4-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x1000 0x3000 with RWX for r1
r1 = Exclusive 0x1000 0x3000 with RWX mapped Remapped(0x0)
|indices: 1->r0 3->td1
"#;
    assert_eq!(display, expected);

    // Now parse.
    let mut parser = Parser::new();
    parser.parse_attestation(display).unwrap();

    let td0_r = parser.domains.get("td0").unwrap();
    let display = format!("{}", td0_r.borrow());
    assert_eq!(display, expected);
}

#[test]
fn test_parse_with_td1_and_regions() {
    // Initial setup
    let (mut engine, td0, _r0, td0_r0) = setup_engine_with_root();

    let c_access = Access::new(0x1000, 0x2000, Rights::all());
    let carved = engine.carve(td0.clone(), td0_r0, &c_access).unwrap();

    let a_access = Access::new(0x3000, 0x1000, Rights::all());
    let alias = engine.alias(td0.clone(), td0_r0, &a_access).unwrap();

    // Create a child domain.
    let ipolicy = InterruptPolicy::default_none();

    let td1 = engine
        .create(&td0.clone(), 0b1, MonitorAPI::empty(), ipolicy)
        .unwrap();
    engine
        .send(
            td0.clone(),
            td1,
            carved,
            Remapped::Remapped(0x0),
            Attributes::empty(),
        )
        .unwrap();
    engine
        .send(
            td0.clone(),
            td1,
            alias,
            Remapped::Remapped(0x2000),
            Attributes::empty(),
        )
        .unwrap();
    engine.seal(td0.clone(), td1).unwrap();

    // Check the display
    let display = format!("{}", td0.borrow());
    let expected = r#"td0 = Sealed domain(td1,r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Sealed domain(r1,r2)
|cores: 0x1
|mon.api: 0x0
|vec0-255: NOT REPORTED, r: 0xffffffffffffffff, w: 0xffffffffffffffff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x1000 0x3000 with RWX for r1
| Alias at 0x3000 0x4000 with RWX for r2
r1 = Exclusive 0x1000 0x3000 with RWX mapped Remapped(0x0)
r2 = Aliased 0x3000 0x4000 with RWX mapped Remapped(0x2000)
|indices: 1->r0 4->td1
"#;
    assert_eq!(display, expected);

    // Now parse.
    let mut parser = Parser::new();
    parser.parse_attestation(display).unwrap();

    let td0_r = parser.domains.get("td0").unwrap();
    let display = format!("{}", td0_r.borrow());
    assert_eq!(display, expected);
}

#[test]
fn test_invalid_td0() {
    let _correct = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;

    let missing_cores = r#"td0 = Sealed domain(r0)
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;

    let missing_api = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;

    let missing_vec = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;

    let incorrect_vector = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWEDVISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;

    let incorrect_hex = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWEDVISIBLE, r: 0x4G, w: 0x5H0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;

    let values = [
        missing_cores,
        missing_api,
        missing_vec,
        incorrect_vector,
        incorrect_hex,
    ];
    for i in values.iter() {
        let mut parser = Parser::new();
        assert!(parser.parse_attestation(i.to_string()).is_err());
    }
}

#[test]
fn test_enumerate_attest() {
    // Initial setup
    let (mut engine, td0, _r0, td0_r0) = setup_engine_with_root();

    // Test attestation.
    let attestation = engine.attest(td0.clone(), None).unwrap();
    let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
    assert_eq!(attestation, expected);

    // Now enumerate r0.
    let enumeration = engine.enumerate(td0.clone(), td0_r0).unwrap();
    let expected = r#"Exclusive 0x0 0x10000 with RWX mapped Identity"#;
    assert_eq!(enumeration, expected);

    // Start building more complex example.
    let td1 = engine
        .create(
            &td0.clone(),
            0x1,
            MonitorAPI::empty(),
            InterruptPolicy::default_all(),
        )
        .unwrap();

    let r1 = engine
        .carve(
            td0.clone(),
            td0_r0,
            &Access::new(0x2000, 0x1000, Rights::READ),
        )
        .unwrap();

    // Attestation td0.
    let attestation = engine.attest(td0.clone(), None).unwrap();
    let expected = r#"td0 = Sealed domain(td1,r0,r1)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Unsealed domain()
|cores: 0x1
|mon.api: 0x0
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x2000 0x3000 with R__ for r1
r1 = Exclusive 0x2000 0x3000 with R__ mapped Identity
|indices: 1->r0 2->td1 3->r1
"#;
    assert_eq!(attestation, expected);

    // Enumerate td1.
    let enumeration = engine.enumerate(td0.clone(), r1).unwrap();
    let expected = r#"Exclusive 0x2000 0x3000 with R__ mapped Identity"#;
    assert_eq!(enumeration, expected);
    // Enumerate td0.
    let enumeration = engine.enumerate(td0.clone(), td0_r0).unwrap();
    let expected = r#"Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x2000 0x3000 with R__ for .0"#;
    assert_eq!(enumeration, expected);

    // Does the index change if we revoke the child?
    let r2 = engine
        .carve(
            td0.clone(),
            td0_r0,
            &Access::new(0x3000, 0x1000, Rights::READ | Rights::WRITE),
        )
        .unwrap();

    let enumeration = engine.enumerate(td0.clone(), td0_r0).unwrap();
    let expected = r#"Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x2000 0x3000 with R__ for .0
| Carve at 0x3000 0x4000 with RW_ for .1"#;
    assert_eq!(enumeration, expected);

    // Revoke the first.
    engine.revoke(td0.clone(), td0_r0, 0).unwrap();
    let enumeration = engine.enumerate(td0.clone(), td0_r0).unwrap();
    let expected = r#"Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x3000 0x4000 with RW_ for .0"#;
    assert_eq!(enumeration, expected);

    // Enumerate the local capa indices.
    let attestation = engine.attest(td0.clone(), None).unwrap();
    let expected = r#"td0 = Sealed domain(td1,r0,r1)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
td1 = Unsealed domain()
|cores: 0x1
|mon.api: 0x0
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
| Carve at 0x3000 0x4000 with RW_ for r1
r1 = Exclusive 0x3000 0x4000 with RW_ mapped Identity
|indices: 1->r0 2->td1 4->r1
"#;
    assert_eq!(attestation, expected);

    // Send the region to td1.
    engine
        .send(
            td0.clone(),
            td1,
            r2,
            Remapped::Identity,
            Attributes::empty(),
        )
        .unwrap();
    engine.revoke(td0.clone(), td1, 0).unwrap();

    // Check we got back to the expected configuration.
    let attestation = engine.attest(td0.clone(), None).unwrap();
    let expected = r#"td0 = Sealed domain(r0)
|cores: 0xffff
|mon.api: 0x1fff
|vec0-255: ALLOWED|VISIBLE, r: 0x0, w: 0x0
r0 = Exclusive 0x0 0x10000 with RWX mapped Identity
|indices: 1->r0
"#;
    assert_eq!(attestation, expected);
}
