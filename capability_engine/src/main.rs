use capa_engine::*;

fn create_root() -> Capability<MemoryRegion> {
    Capability::<MemoryRegion>::new(MemoryRegion {
        kind: RegionKind::Carve,
        status: Status::Exclusive,
        access: Access::new(0, 0x10000, Rights::READ | Rights::WRITE | Rights::EXECUTE),
        attributes: Attributes::NONE,
        remapped: Remapped::Identity,
    })
}

fn main() {
    let mut root = create_root();
    let _ = root
        .carve(&Access::new(0x2000, 0x1000, Rights::READ | Rights::WRITE))
        .unwrap();
    let a1 = root
        .alias(&Access::new(
            0x0000,
            0x2000,
            Rights::READ | Rights::WRITE | Rights::EXECUTE,
        ))
        .expect("Error");

    {
        // Borrow the capability mutably
        let a1_borrow = &mut a1.borrow_mut();

        // Now you can call carve on the actual Capability<MemoryRegion>
        let _ = a1_borrow.carve(&Access::new(
            0x0000,
            0x1000,
            Rights::READ | Rights::WRITE | Rights::EXECUTE,
        ));
    } // The mutable borrow goes out of scope here

    // Now it is safe to print the capabilities because no mutable borrow exists
    println!("The root capability:\n{}", root);
    println!("The alias child:\n{}", a1.borrow());
}
