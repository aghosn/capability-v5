use std::{cell::RefCell, rc::Rc};

use crate::{
    core::{
        capability::{CapaRef, Capability},
        domain::{
            Domain, Field, FieldType, InterruptPolicy, LocalCapa, MonitorAPI, Policies, Status,
        },
        memory_region::{Access, Attributes, Remapped, Rights},
    },
    server::engine::Engine,
    CallInterface, EngineInterface,
};

use super::engine::{ClientError, ClientResult, CommunicationInterface};

pub struct LocalClient {
    pub server: Engine,
    pub current: CapaRef<Domain>,
}

impl CommunicationInterface for LocalClient {
    fn init() -> Self {
        let engine = Engine::new();
        let policies = Policies::new(
            !(0 as u64),
            MonitorAPI::all(),
            InterruptPolicy::default_all(),
        );
        let mut capa = Capability::<Domain>::new(Domain::new(policies));
        capa.data.status = Status::Sealed;
        let ref_td = Rc::new(RefCell::new(capa));
        Self {
            server: engine,
            current: ref_td,
        }
    }

    fn send(
        &self,
        call: crate::CallInterface,
        args: &[u64; 6],
    ) -> Result<ClientResult, ClientError> {
        // match the call, execute it on the local machine.
        match call {
            CallInterface::SET => {
                let field_type = FieldType::from_u64(args[2]).ok_or(ClientError::FailedSet)?;
                ClientResult::wrap_empty(self.server.set(
                    self.current.clone(),
                    args[0] as LocalCapa,
                    args[1],
                    field_type,
                    args[3] as Field,
                    args[4],
                ))
            }
            CallInterface::GET => {
                let field_type = FieldType::from_u64(args[2]).ok_or(ClientError::FailedSet)?;
                ClientResult::wrap_value(self.server.get(
                    self.current.clone(),
                    args[0] as LocalCapa,
                    args[1],
                    field_type,
                    args[3] as Field,
                ))
            }
            CallInterface::SEAL => ClientResult::wrap_empty(
                self.server.seal(self.current.clone(), args[0] as LocalCapa),
            ),
            CallInterface::SEND => {
                let remap = if args[2] == 0 {
                    Remapped::Identity
                } else {
                    Remapped::Remapped(args[3] as u64)
                };
                ClientResult::wrap_empty(self.server.send(
                    self.current.clone(),
                    args[0] as LocalCapa,
                    args[1] as LocalCapa,
                    remap,
                    Attributes::from_bits_truncate(args[4] as u8),
                ))
            }
            CallInterface::ALIAS => {
                let access = Access::new(
                    args[1] as u64,
                    args[2] as u64,
                    Rights::from_bits_truncate(args[3] as u8),
                );
                ClientResult::wrap_value(self.server.alias(
                    self.current.clone(),
                    args[0] as LocalCapa,
                    &access,
                ))
            }
            CallInterface::CARVE => {
                let access = Access::new(
                    args[1] as u64,
                    args[2] as u64,
                    Rights::from_bits_truncate(args[3] as u8),
                );
                ClientResult::wrap_value(self.server.carve(
                    self.current.clone(),
                    args[0] as LocalCapa,
                    &access,
                ))
            }
            CallInterface::CREATE => ClientResult::wrap_value(self.server.create(
                &self.current.clone(),
                args[0],
                MonitorAPI::from_bits_truncate(args[1] as u16),
                InterruptPolicy::default_none(),
            )),
            CallInterface::ATTEST => {
                let other = if args[0] != 0 {
                    Some(args[0] as LocalCapa)
                } else {
                    None
                };
                ClientResult::wrap_string(self.server.attest(self.current.clone(), other))
            }
            CallInterface::SWITCH => {
                todo!()
            }
            CallInterface::REVOKE => ClientResult::wrap_empty(self.server.revoke(
                self.current.clone(),
                args[0] as LocalCapa,
                args[1],
            )),
            CallInterface::ENUMERATE => ClientResult::wrap_string(
                self.server
                    .enumerate(self.current.clone(), args[0] as LocalCapa),
            ),
        }
    }

    // This is local, we do not care about the receive.
    fn receive(
        &self,
        _engine: &mut crate::server::engine::Engine,
        call: crate::CallInterface,
        args: &[u64; 6],
    ) -> Result<ClientResult, ClientError> {
        self.send(call, args)
    }
}
