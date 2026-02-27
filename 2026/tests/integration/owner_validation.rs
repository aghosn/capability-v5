//! Tests for owner domain validation: sealed check and MonitorAPI enforcement

use capability_engine::*;
use std::sync::Arc;
use parking_lot::RwLock;

/// Helper: create a sealed domain capability with given API, and a memory capability owned by it.
/// Returns (domain_capa, memory_capa).
fn setup_domain_with_memory(
    api: MonitorAPI,
) -> (CapabilityRef<Domain>, CapabilityRef<MemoryRegion>) {
    // Create a sealed domain
    let mut domain = Domain::new(DomainPolicy::new_restricted(0b1111, api));
    domain.seal().unwrap();
    let domain_capa: CapabilityRef<Domain> = Arc::new(RwLock::new(Capability {
        owned: Ownership::new(0, 0),
        data: domain,
        parent: std::sync::Weak::new(),
        children: Vec::new(),
    }));

    // Create a memory capability owned by this domain
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let mut ownership = Ownership::new(domain_capa.read().data.id, 1);
    ownership.set_owner_domain(Arc::downgrade(&domain_capa));
    let mem_capa: CapabilityRef<MemoryRegion> = Arc::new(RwLock::new(Capability {
        owned: ownership,
        data: region,
        parent: std::sync::Weak::new(),
        children: Vec::new(),
    }));

    (domain_capa, mem_capa)
}

/// Helper: create an unsealed domain capability and a memory capability owned by it.
fn setup_unsealed_domain_with_memory() -> (CapabilityRef<Domain>, CapabilityRef<MemoryRegion>) {
    let domain = Domain::new(DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    // Domain is NOT sealed
    let domain_capa: CapabilityRef<Domain> = Arc::new(RwLock::new(Capability {
        owned: Ownership::new(0, 0),
        data: domain,
        parent: std::sync::Weak::new(),
        children: Vec::new(),
    }));

    let region = MemoryRegion::new_root(0x0, 0x10000);
    let mut ownership = Ownership::new(domain_capa.read().data.id, 1);
    ownership.set_owner_domain(Arc::downgrade(&domain_capa));
    let mem_capa: CapabilityRef<MemoryRegion> = Arc::new(RwLock::new(Capability {
        owned: ownership,
        data: region,
        parent: std::sync::Weak::new(),
        children: Vec::new(),
    }));

    (domain_capa, mem_capa)
}

// ==================== Unsealed Domain Rejection ====================

#[test]
fn test_unsealed_domain_cannot_alias() {
    let (_dom, mem) = setup_unsealed_domain_with_memory();
    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = Capability::alias_child(&mem, access, 1, 10);
    assert!(matches!(result, Err(CapaError::DomainNotSealed)));
}

#[test]
fn test_unsealed_domain_cannot_carve() {
    let (_dom, mem) = setup_unsealed_domain_with_memory();
    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = Capability::carve_child(&mem, access, 1, 10);
    assert!(matches!(result, Err(CapaError::DomainNotSealed)));
}

#[test]
fn test_unsealed_domain_cannot_send() {
    let (_dom, mem) = setup_unsealed_domain_with_memory();
    let result = Capability::send_to(&mem, 99, 10, Attributes::NONE);
    assert!(matches!(result, Err(CapaError::DomainNotSealed)));
}

#[test]
fn test_unsealed_domain_cannot_revoke() {
    // Set up with a sealed domain first to create a child, then make it unsealed
    let (dom, mem) = setup_domain_with_memory(MonitorAPI::ALL);

    // Carve a child while sealed
    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child, _) = Capability::carve_child(&mem, access, dom.read().data.id, 10).unwrap();

    // Unseal the domain by creating a new unsealed one and swapping
    // Instead, create a fresh unsealed setup with a child already present
    let (_dom2, mem2) = setup_unsealed_domain_with_memory();
    // Add a dummy child to mem2
    let child_region = MemoryRegion::new_root(0x1000, 0x1000);
    let child_capa: CapabilityRef<MemoryRegion> = Capability::new_child(
        99, 20, child_region, Arc::downgrade(&mem2),
    );
    mem2.write().add_child(child_capa);

    let result = Capability::revoke_child(&mem2, 20);
    assert!(matches!(result, Err(CapaError::DomainNotSealed)));
}

// ==================== MonitorAPI Enforcement ====================

#[test]
fn test_api_no_alias_permission() {
    // Domain has all permissions EXCEPT alias
    let api = MonitorAPI::from_bits(MonitorAPI::ALL.bits() & !MonitorAPI::ALIAS);
    let (_dom, mem) = setup_domain_with_memory(api);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = Capability::alias_child(&mem, access, 1, 10);
    assert!(matches!(result, Err(CapaError::ApiNotAllowed)));
}

#[test]
fn test_api_no_carve_permission() {
    let api = MonitorAPI::from_bits(MonitorAPI::ALL.bits() & !MonitorAPI::CARVE);
    let (_dom, mem) = setup_domain_with_memory(api);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = Capability::carve_child(&mem, access, 1, 10);
    assert!(matches!(result, Err(CapaError::ApiNotAllowed)));
}

#[test]
fn test_api_no_send_permission() {
    let api = MonitorAPI::from_bits(MonitorAPI::ALL.bits() & !MonitorAPI::SEND);
    let (_dom, mem) = setup_domain_with_memory(api);

    let result = Capability::send_to(&mem, 99, 10, Attributes::NONE);
    assert!(matches!(result, Err(CapaError::ApiNotAllowed)));
}

#[test]
fn test_api_no_revoke_permission() {
    let api = MonitorAPI::from_bits(MonitorAPI::ALL.bits() & !MonitorAPI::REVOKE);
    let (_dom, mem) = setup_domain_with_memory(api);

    // First create a child (carve is allowed)
    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child, _) = Capability::carve_child(&mem, access, 1, 10).unwrap();

    let result = Capability::revoke_child(&mem, 10);
    assert!(matches!(result, Err(CapaError::ApiNotAllowed)));
}

#[test]
fn test_api_no_create_permission_for_domain() {
    let api = MonitorAPI::from_bits(MonitorAPI::ALL.bits() & !MonitorAPI::CREATE);
    let mut domain = Domain::new(DomainPolicy::new_restricted(0b1111, api));
    domain.seal().unwrap();
    let domain_capa: CapabilityRef<Domain> = Arc::new(RwLock::new(Capability {
        owned: Ownership::new(0, 0),
        data: domain,
        parent: std::sync::Weak::new(),
        children: Vec::new(),
    }));

    // Create a domain capability owned by this domain
    let parent_domain = Domain::new_root(4);
    let mut ownership = Ownership::new(domain_capa.read().data.id, 1);
    ownership.set_owner_domain(Arc::downgrade(&domain_capa));
    let parent_dom_capa: CapabilityRef<Domain> = Arc::new(RwLock::new(Capability {
        owned: ownership,
        data: parent_domain,
        parent: std::sync::Weak::new(),
        children: Vec::new(),
    }));

    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let result = Capability::create_child_domain(&parent_dom_capa, child_policy, 1, 10);
    assert!(matches!(result, Err(CapaError::ApiNotAllowed)));
}

// ==================== Sealed + Allowed Succeeds ====================

#[test]
fn test_sealed_domain_with_alias_permission_can_alias() {
    let (_dom, mem) = setup_domain_with_memory(MonitorAPI::ALL);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = Capability::alias_child(&mem, access, 1, 10);
    assert!(result.is_ok());
}

#[test]
fn test_sealed_domain_with_carve_permission_can_carve() {
    let (_dom, mem) = setup_domain_with_memory(MonitorAPI::ALL);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = Capability::carve_child(&mem, access, 1, 10);
    assert!(result.is_ok());
}

#[test]
fn test_sealed_domain_with_send_permission_can_send() {
    let (_dom, mem) = setup_domain_with_memory(MonitorAPI::ALL);

    let result = Capability::send_to(&mem, 99, 10, Attributes::NONE);
    assert!(result.is_ok());
}

#[test]
fn test_sealed_domain_with_revoke_permission_can_revoke() {
    let (_dom, mem) = setup_domain_with_memory(MonitorAPI::ALL);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child, _) = Capability::carve_child(&mem, access, 1, 10).unwrap();

    let result = Capability::revoke_child(&mem, 10);
    assert!(result.is_ok());
}

// ==================== Revoked Domain Rejection ====================

#[test]
fn test_revoked_domain_cannot_alias() {
    let (dom, mem) = setup_domain_with_memory(MonitorAPI::ALL);

    // Drop the domain capability (simulates revocation — weak ref won't upgrade)
    drop(dom);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = Capability::alias_child(&mem, access, 1, 10);
    assert!(matches!(result, Err(CapaError::PermissionDenied)));
}

#[test]
fn test_revoked_domain_cannot_carve() {
    let (dom, mem) = setup_domain_with_memory(MonitorAPI::ALL);
    drop(dom);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = Capability::carve_child(&mem, access, 1, 10);
    assert!(matches!(result, Err(CapaError::PermissionDenied)));
}

#[test]
fn test_revoked_domain_cannot_send() {
    let (dom, mem) = setup_domain_with_memory(MonitorAPI::ALL);
    drop(dom);

    let result = Capability::send_to(&mem, 99, 10, Attributes::NONE);
    assert!(matches!(result, Err(CapaError::PermissionDenied)));
}

// ==================== Send clears owner_domain ====================

#[test]
fn test_send_clears_owner_domain() {
    let (_dom, mem) = setup_domain_with_memory(MonitorAPI::ALL);

    // After send, the owner_domain should be cleared
    Capability::send_to(&mem, 99, 10, Attributes::NONE).unwrap();
    assert!(mem.read().owned.owner_domain.is_none());
}

// ==================== Extension trait methods validate too ====================

#[test]
fn test_extension_trait_alias_validates() {
    let (_dom, mem) = setup_unsealed_domain_with_memory();
    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = mem.alias(access, 10);
    assert!(matches!(result, Err(CapaError::DomainNotSealed)));
}

#[test]
fn test_extension_trait_carve_validates() {
    let (_dom, mem) = setup_unsealed_domain_with_memory();
    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = mem.carve(access, 10);
    assert!(matches!(result, Err(CapaError::DomainNotSealed)));
}

#[test]
fn test_extension_trait_send_validates() {
    let (_dom, mem) = setup_unsealed_domain_with_memory();
    let result = mem.send(99, 10, Attributes::NONE);
    assert!(matches!(result, Err(CapaError::DomainNotSealed)));
}

// ==================== Minimal API: only the needed permission ====================

#[test]
fn test_only_alias_permission_suffices() {
    let api = MonitorAPI::from_bits(MonitorAPI::ALIAS);
    let (_dom, mem) = setup_domain_with_memory(api);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = Capability::alias_child(&mem, access, 1, 10);
    assert!(result.is_ok());
}

#[test]
fn test_only_carve_permission_suffices() {
    let api = MonitorAPI::from_bits(MonitorAPI::CARVE);
    let (_dom, mem) = setup_domain_with_memory(api);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = Capability::carve_child(&mem, access, 1, 10);
    assert!(result.is_ok());
}

#[test]
fn test_only_send_permission_suffices() {
    let api = MonitorAPI::from_bits(MonitorAPI::SEND);
    let (_dom, mem) = setup_domain_with_memory(api);

    let result = Capability::send_to(&mem, 99, 10, Attributes::NONE);
    assert!(result.is_ok());
}
