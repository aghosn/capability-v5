use capa_engine::core::coalesced::CoalescedView;
use capa_engine::core::memory_region::{Access, Remapped, Rights, ViewRegion};

// ———————————————————————————————— Helpers ————————————————————————————————— //

fn assert_view_display_eq(coal: &CoalescedView, expected: &[&str]) {
    let rendered: Vec<String> = coal.regions().iter().map(|v| v.to_string()).collect();
    assert_eq!(rendered.len(), expected.len(), "Length mismatch");

    for (i, (actual, expect)) in rendered.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            actual, expect,
            "Mismatch at index {}: got `{}`, expected `{}`",
            i, actual, expect
        );
    }
}
// ————————————————————————————————— Tests —————————————————————————————————— //

#[test]
fn test_coalesce() {
    let vr1 = ViewRegion {
        access: Access {
            start: 0,
            size: 0x1000,
            rights: Rights::READ,
        },
        remap: Remapped::Identity,
    };

    let vr2 = ViewRegion {
        access: Access {
            start: 0x1000,
            size: 0x2000,
            rights: Rights::READ,
        },
        remap: Remapped::Identity,
    };

    let view = CoalescedView::new() + vr1 + vr2;
    let expected = vec!["0x0 0x3000 with R__ mapped Identity"];
    assert_view_display_eq(&view, &expected);

    let removed = view
        - ViewRegion {
            access: Access {
                start: 0x1000,
                size: 0x1000,
                rights: Rights::READ,
            },
            remap: Remapped::Identity,
        };
    let expected = vec![
        "0x0 0x1000 with R__ mapped Identity",
        "0x2000 0x3000 with R__ mapped Identity",
    ];
    assert_view_display_eq(&removed, &expected)
}
