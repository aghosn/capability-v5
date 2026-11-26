use alloc::sync::Arc;

use crate::{
    Capability, CapabilityRef, CapaError, Domain, DomainId, InterruptVisibility, LocalHandle,
    MonitorAPI, Platform, Result, SubHandle, SwitchContext, UpdateBatch,
};

/// Refers to the caller's own domain node in generic tree operations.
pub const SELF_CAPABILITY: LocalHandle = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoorbellKind {
    Sync,
    Async { vp_id: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Doorbell {
    pub recipient: DomainId,
    pub port_id: SubHandle,
    pub vector: u8,
    pub kind: DoorbellKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoorbellNotification {
    pub source: DomainId,
    pub source_vp: u64,
    pub doorbell: Doorbell,
    pub recipient_vp: u64,
    pub value: u64,
}

pub(crate) fn check_vector(domain: &Domain, vp_id: u64, vector: u8) -> Result<()> {
    domain.policy.vprocessor_states.iter().find(|vp| vp.id == vp_id)
        .ok_or(CapaError::NotFound)?;
    let policy = domain.policy.interrupt_action(vp_id, vector);
    if policy.visibility != InterruptVisibility::Deliver || !policy.injectable {
        return Err(CapaError::PermissionDenied);
    }
    Ok(())
}

impl Capability<Domain> {
    pub fn doorbell_info(&self) -> Option<Doorbell> {
        self.data.doorbell
    }

    pub(crate) fn validate_doorbell_policy(
        recipient: &Capability<Domain>,
        policy: &crate::DomainPolicy,
    ) -> Result<()> {
        for endpoint in &recipient.children {
            if let Some(doorbell) = endpoint.read().data.doorbell {
                let allowed = |vp| {
                    let vector = policy.interrupt_action(vp, doorbell.vector);
                    vector.visibility == InterruptVisibility::Deliver && vector.injectable
                };
                let valid = match doorbell.kind {
                    DoorbellKind::Sync => policy.vprocessor_states.iter().any(|vp| allowed(vp.id)),
                    DoorbellKind::Async { vp_id } => {
                        policy.vprocessor_states.iter().any(|vp| vp.id == vp_id) && allowed(vp_id)
                    }
                };
                if !valid {
                    return Err(CapaError::PermissionDenied);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn resolve_endpoint(
        caller: &CapabilityRef<Domain>,
        handle: LocalHandle,
    ) -> Result<CapabilityRef<Domain>> {
        let c = caller.read();
        if c.data.is_revoked() {
            return Err(CapaError::DomainRevoked);
        }
        let endpoint = c.data.get_domain_capability(handle)
            .and_then(|weak| weak.upgrade()).ok_or(CapaError::NotFound)?;
        {
            let e = endpoint.read();
            if !e.is_endpoint() || e.data.is_revoked() || e.owned.owner != c.data.id {
                return Err(CapaError::PermissionDenied);
            }
        }
        Ok(endpoint)
    }

    pub fn create_doorbell(
        platform: &dyn Platform,
        caller: &CapabilityRef<Domain>,
        child: Option<LocalHandle>,
        vector: u8,
        kind: DoorbellKind,
    ) -> Result<(LocalHandle, SubHandle)> {
        crate::platform::execute(platform, true, || {
            caller.read().data.require_api(MonitorAPI::CREATE_DOORBELL)?;
            if vector < 32 {
                return Err(CapaError::InvalidValue);
            }
            let owner = caller.read().data.id;
            let recipient = match child {
                None => caller.clone(),
                Some(handle) => {
                    let c = caller.read();
                    if c.data.is_domain_handle_frozen(handle) {
                        return Err(CapaError::PermissionDenied);
                    }
                    let target = c.data.get_domain_capability(handle)
                        .and_then(|weak| weak.upgrade()).ok_or(CapaError::NotFound)?;
                    drop(c);
                    {
                        let t = target.read();
                        if t.is_endpoint() || t.owned.owner != owner || t.data.is_revoked() {
                            return Err(CapaError::PermissionDenied);
                        }
                        if t.data.is_sealed() {
                            return Err(CapaError::DomainSealed);
                        }
                    }
                    target
                }
            };
            let (port, depth, id) = {
                let r = recipient.read();
                match kind {
                    DoorbellKind::Async { vp_id } => check_vector(&r.data, vp_id, vector)?,
                    DoorbellKind::Sync => {
                        // Sync resolves its actual VP at invocation, but creation
                        // must not authorize a vector disallowed on every VP.
                        if !r.data.policy.vprocessor_states.iter()
                            .any(|vp| check_vector(&r.data, vp.id, vector).is_ok())
                        {
                            return Err(CapaError::PermissionDenied);
                        }
                    }
                }
                r.next_child_sub.checked_add(1).ok_or(CapaError::NoMemory)?;
                (r.next_child_sub, r.depth + 1, r.data.id)
            };
            let mut data = Domain::new_sentinel();
            data.doorbell = Some(Doorbell { recipient: id, port_id: port, vector, kind });
            let endpoint = Capability::new_child(owner, port, depth, data, Arc::downgrade(&recipient));
            {
                let mut e = endpoint.write();
                e.channel_target = Some(Arc::downgrade(&recipient));
                e.owned.owner_domain = Some(Arc::downgrade(caller));
            }
            {
                let mut r = recipient.write();
                r.next_child_sub += 1;
                r.add_child(endpoint.clone());
            }
            let handle = {
                let mut c = caller.write();
                let handle = c.data.allocate_domain_handle();
                c.data.add_domain_capability(handle, Arc::downgrade(&endpoint));
                handle
            };
            Ok(((handle, port), UpdateBatch::new()))
        }).map(|(result, _)| result)
    }

    pub fn notify(
        platform: &dyn Platform,
        caller: &CapabilityRef<Domain>,
        handle: LocalHandle,
        value: u64,
    ) -> Result<Option<SwitchContext>> {
        let core_id = platform.get_current_core().ok_or(CapaError::InvalidValue)?;
        crate::platform::execute(platform, false, || {
            crate::domain_api::apply_core_updates(platform, core_id)?;
            caller.read().data.require_api(MonitorAPI::NOTIFY)?;
            let endpoint = Self::resolve_endpoint(caller, handle)?;
            let (doorbell, recipient) = {
                let e = endpoint.read();
                let doorbell = e.data.doorbell.ok_or(CapaError::PermissionDenied)?;
                let recipient = e.channel_target.as_ref().and_then(|weak| weak.upgrade())
                    .ok_or(CapaError::NotFound)?;
                (doorbell, recipient)
            };
            let (source, source_vp) = {
                let c = caller.read();
                if c.data.is_domain_handle_frozen(handle) {
                    return Err(CapaError::PermissionDenied);
                }
                let binding = platform.switch_manager().get_core(core_id)?
                    .current_binding().ok_or(CapaError::InvalidValue)?;
                if !Arc::ptr_eq(&binding.domain, caller) {
                    return Err(CapaError::PermissionDenied);
                }
                let vp = c.data.find_vp_on_core(core_id).ok_or(CapaError::InvalidValue)?;
                if vp.id != binding.vp_id {
                    return Err(CapaError::PermissionDenied);
                }
                (c.data.id, vp.id)
            };
            if recipient.read().data.is_revoked() {
                return Err(CapaError::DomainRevoked);
            }
            let prepared = match doorbell.kind {
                DoorbellKind::Sync => Some(Self::prepare_vp_interrupt(
                    platform, caller, core_id, doorbell.vector, Some(doorbell.recipient),
                )?),
                DoorbellKind::Async { .. } => None,
            };
            let recipient_vp = match &prepared {
                Some(unwind) => unwind.context.to_vp_id.ok_or(CapaError::InvalidValue)?,
                None => match doorbell.kind {
                    DoorbellKind::Async { vp_id } => vp_id,
                    DoorbellKind::Sync => unreachable!(),
                },
            };
            check_vector(&recipient.read().data, recipient_vp, doorbell.vector)?;
            let notification = DoorbellNotification {
                source, source_vp, doorbell, recipient_vp, value,
            };
            let mut prepared = prepared;
            let mut context = None;
            platform.commit_doorbell(&notification, &mut || {
                if let Some(unwind) = prepared.take() {
                    context = Some(unwind.commit(platform));
                }
            })?;
            Ok((context, UpdateBatch::new()))
        }).map(|(context, _)| context)
    }

    pub(crate) fn revoke_domain_child_inner(
        platform: &dyn Platform,
        caller: &CapabilityRef<Domain>,
        parent_handle: LocalHandle,
        child_sub: SubHandle,
    ) -> Result<UpdateBatch> {
        caller.read().data.require_api(MonitorAPI::REVOKE)?;
        let parent = if parent_handle == SELF_CAPABILITY {
            caller.clone()
        } else {
            let c = caller.read();
            if c.data.is_domain_handle_frozen(parent_handle) {
                return Err(CapaError::PermissionDenied);
            }
            c.data.get_domain_capability(parent_handle)
                .and_then(|weak| weak.upgrade()).ok_or(CapaError::NotFound)?
        };
        let child = {
            let p = parent.read();
            if p.is_endpoint() || p.data.is_revoked() {
                return Err(CapaError::PermissionDenied);
            }
            p.children.iter().find(|child| child.read().sub_handle == child_sub)
                .cloned().ok_or(CapaError::NotFound)?
        };
        Self::validate_revoke_domain_subtree(platform, &child)?;
        parent.write().remove_child(child_sub).ok_or(CapaError::NotFound)?;
        let parent_id = parent.read().data.id;
        Self::revoke_domain_subtree(platform, &child, Some(parent_id))
    }

    pub(crate) fn revoke_endpoint(endpoint: &CapabilityRef<Domain>) -> Result<UpdateBatch> {
        let (holder, pending_receiver) = {
            let mut e = endpoint.write();
            e.data.revoke();
            (e.owned.owner_domain.as_ref().and_then(|w| w.upgrade()),
             e.owned.pending_receiver.take().and_then(|w| w.upgrade()))
        };
        if let Some(receiver) = pending_receiver {
            receiver.write().data.pending_domain_capabilities.retain(|_, pending| {
                !pending.cap.upgrade().is_some_and(|cap| Arc::ptr_eq(&cap, endpoint))
            });
        }
        if let Some(holder) = holder {
            let mut h = holder.write();
            let handle = h.data.domain_capabilities.iter().find_map(|(handle, weak)| {
                weak.upgrade().filter(|cap| Arc::ptr_eq(cap, endpoint)).map(|_| *handle)
            });
            if let Some(handle) = handle {
                h.data.unfreeze_domain_handle(handle);
                h.data.remove_domain_capability(handle);
            }
        }
        Ok(UpdateBatch::new())
    }
}
