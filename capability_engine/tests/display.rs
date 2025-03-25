use capa_engine::capability::*;
use capa_engine::memory_region::*;

fn create_root() -> Capability<MemoryRegion> {
    Capability::<MemoryRegion>::new(MemoryRegion {
        kind: RegionKind::Carve,
        status: Status::Exclusive,
        access: Access::new(0, 0x10000, Rights::READ | Rights::WRITE | Rights::EXECUTE),
        attributes: Attributes::NONE,
        remapped: Remapped::Identity,
    })
}

#[test]
fn test_display_single_node() {
    let root = create_root();
    let display_output = format!("{}", root);

    let expected_output = "Exclusive 0x0 0x10000 with RWX mapped Identity";

    // Check if the display output matches the expected output
    assert_eq!(display_output, expected_output);
}

#[test]
fn test_display_with_alias() {
    let mut root = create_root();
    let alias_access = Access::new(
        0x2000,
        0x1000,
        Rights::READ | Rights::WRITE | Rights::EXECUTE,
    );
    let a1 = root.alias(&alias_access).expect("Error");

    // Get the display output of the root capability with its alias
    let display_output = format!("{}", root);

    let expected_output = r#"Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x2000 0x3000 with RWX for .0"#;

    // Check if the display output contains the root and child
    assert_eq!(display_output, expected_output);

    // Check the child.
    let display_output = format!("{}", a1.borrow());
    let expected_output = "Aliased 0x2000 0x3000 with RWX mapped Identity";

    assert_eq!(display_output, expected_output);
}

#[test]
fn test_display_with_multiple_children() {
    let mut root = create_root();
    let alias_access = Access::new(
        0x2000,
        0x1000,
        Rights::READ | Rights::WRITE | Rights::EXECUTE,
    );
    let a1 = root.alias(&alias_access).expect("Error");

    let carve_access = Access::new(0x3000, 0x1000, Rights::READ | Rights::WRITE);
    let c1 = root.carve(&carve_access).expect("Error");

    // Get the display output of the root capability with its children
    let display_output = format!("{}", root);

    let expected_output = r#"Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x2000 0x3000 with RWX for .0
| Carve at 0x3000 0x4000 with RW_ for .1"#;

    // Check if the display output contains the root and children
    assert_eq!(display_output, expected_output);

    // Check the children now.
    let display_output = format!("{}", a1.borrow());
    let expected_output = "Aliased 0x2000 0x3000 with RWX mapped Identity";
    assert_eq!(display_output, expected_output);

    let display_output = format!("{}", c1.borrow());
    let expected_output = "Exclusive 0x3000 0x4000 with RW_ mapped Identity";
    assert_eq!(display_output, expected_output);
}

#[test]
fn test_display_with_nested_children() {
    let mut root = create_root();
    let alias_access = Access::new(
        0x2000,
        0x2000,
        Rights::READ | Rights::WRITE | Rights::EXECUTE,
    );
    let a1 = root.alias(&alias_access).expect("Error");

    let carve_access = Access::new(0x3000, 0x1000, Rights::READ | Rights::WRITE);
    let c1 = a1.borrow_mut().carve(&carve_access).expect("Error");

    // Get the display output of the root capability with its alias and nested carve
    let display_output = format!("{}", root);

    let expected_output = r#"Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x2000 0x4000 with RWX for .0"#; // Nested carve should also be .0

    // Check if the display output contains the root and nested child
    assert_eq!(display_output, expected_output);

    // Check the alias.
    let display_output = format!("{}", a1.borrow());
    let expected_output = r#"Aliased 0x2000 0x4000 with RWX mapped Identity
| Carve at 0x3000 0x4000 with RW_ for .0"#;
    assert_eq!(display_output, expected_output);

    // Check the carve.
    let display_output = format!("{}", c1.borrow());
    let expected_output = "Aliased 0x3000 0x4000 with RW_ mapped Identity";
    assert_eq!(display_output, expected_output);
}

#[test]
fn test_display_with_remap() {
    let mut root = create_root();
    let alias_access = Access::new(
        0x2000,
        0x1000,
        Rights::READ | Rights::WRITE | Rights::EXECUTE,
    );
    let alias_ref = root.alias(&alias_access).expect("Error");

    // Change the remap to a non-identity one
    alias_ref.borrow_mut().data.remapped = Remapped::Remapped(0x1000);

    let display_output = format!("{}", root);

    let expected_output = r#"Exclusive 0x0 0x10000 with RWX mapped Identity
| Alias at 0x2000 0x3000 with RWX for .0"#;

    // Check if the display output contains the remap information
    assert_eq!(display_output, expected_output);

    // Check the remapped in the child.
    let display_output = format!("{}", alias_ref.borrow());
    let expected_output = "Aliased 0x2000 0x3000 with RWX mapped Remapped(0x1000)";
    assert_eq!(display_output, expected_output);
}

// ——————————————————— Testing the display of ViewRegions ——————————————————— //

fn assert_view_display_eq(view: &[ViewRegion], expected: &[&str]) {
    let rendered: Vec<String> = view.iter().map(|v| v.to_string()).collect();
    assert_eq!(rendered.len(), expected.len(), "Length mismatch");

    for (i, (actual, expect)) in rendered.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            actual, expect,
            "Mismatch at index {}: got `{}`, expected `{}`",
            i, actual, expect
        );
    }
}

#[test]
fn test_display_viewregion_identity() {
    let base_access = Access::new(0x0, 0x10000, Rights::READ | Rights::WRITE);
    let region = MemoryRegion {
        kind: RegionKind::Carve,
        status: Status::Exclusive,
        access: base_access,
        attributes: Attributes::NONE,
        remapped: Remapped::Identity,
    };

    let mut cap = Capability::<MemoryRegion>::new(region);

    // Carve out a region in the middle
    let carved = Access::new(0x1000, 0x1000, Rights::READ | Rights::WRITE);
    cap.carve(&carved).unwrap();

    let views = cap.view();

    let expected = vec![
        "0x0 0x1000 with RW_ mapped Identity",
        "0x2000 0x10000 with RW_ mapped Identity",
    ];

    assert_view_display_eq(&views, &expected);
}

#[test]
fn test_display_viewregion_remapped() {
    let base_access = Access::new(0x0, 0x10000, Rights::READ | Rights::WRITE | Rights::EXECUTE);
    let region = MemoryRegion {
        kind: RegionKind::Carve,
        status: Status::Exclusive,
        access: base_access,
        attributes: Attributes::NONE,
        remapped: Remapped::Remapped(0x4000),
    };

    let mut cap = Capability::<MemoryRegion>::new(region);

    // Carve out a region at the start
    let carved = Access::new(
        0x2000,
        0x2000,
        Rights::READ | Rights::WRITE | Rights::EXECUTE,
    );
    cap.carve(&carved).unwrap();

    let views = cap.view();

    let expected = vec![
        "0x0 0x2000 with RWX mapped Remapped(0x4000)",
        "0x4000 0x10000 with RWX mapped Remapped(0x8000)",
    ];

    assert_view_display_eq(&views, &expected);
}

#[test]
fn test_display_viewregion_no_carves() {
    let base_access = Access::new(0x0, 0x10000, Rights::WRITE);
    let region = MemoryRegion {
        kind: RegionKind::Carve,
        status: Status::Exclusive,
        access: base_access,
        attributes: Attributes::NONE,
        remapped: Remapped::Identity,
    };

    let cap = Capability::<MemoryRegion>::new(region);

    let views = cap.view();

    let expected = vec!["0x0 0x10000 with _W_ mapped Identity"];

    assert_view_display_eq(&views, &expected);
}

#[test]
fn test_view_with_alias() {
    let mut capa = Capability::<MemoryRegion>::new(MemoryRegion {
        kind: RegionKind::Carve,
        status: Status::Exclusive,
        access: Access::new(0x1000, 0x1000, Rights::READ | Rights::WRITE),
        attributes: Attributes::NONE,
        remapped: Remapped::Identity,
    });

    capa.alias(&Access::new(0x1400, 0x200, Rights::READ | Rights::WRITE))
        .unwrap(); // should NOT affect view
    let views = capa.view();
    assert_view_display_eq(&views, &vec!["0x1000 0x2000 with RW_ mapped Identity"]);
}
