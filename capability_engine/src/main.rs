use std::cell::RefCell;
use std::rc::Rc;

use capa_engine::capability::*;
use capa_engine::domain::{
    CapaWrapper, Domain, InterruptPolicy, MonitorAPI, Policies, Status as DStatus,
};
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

fn create_root_domain() -> Capability<Domain> {
    let policies = Policies::new(
        !(0 as u64),
        MonitorAPI::all(),
        InterruptPolicy::default_all(),
    );
    let mut capa = Capability::<Domain>::new(Domain::new(policies));
    capa.data.status = DStatus::Sealed;
    capa
}

fn main() {
    let mut domain = create_root_domain();
    let region = create_root();
    let reference = Rc::new(RefCell::new(region));
    domain.data.install(CapaWrapper::Region(reference));
    println!("The root domain:\n{}", domain);
}
