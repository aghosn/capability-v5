//! Phase 7f: Linux kernel + initrd loading via PVH boot protocol.

use crate::serial_println;

use super::{LinuxState, PlatformInfo};

// ── Phase 7f: Linux kernel loading ───────────────────────────────────────── //

/// Phase P7f: load a Linux bzImage into dom0 physical memory, write
/// `struct boot_params`, and patch the VMCS guest `RIP`/`RSP`.
///
/// Entry model: **32-bit protected-mode via the decompressor** (UNRESTRICTED_GUEST,
/// PE=1, no paging).  dom0's page tables are allocated from its own normal memory
/// by the Linux decompressor — Themis has no involvement in CR3 setup.
///
/// The [`LinuxState`] returned carries `boot_params_phys` for use by P7g, which
/// must load it into ESI before executing VMLAUNCH.
pub fn linux(info: &PlatformInfo, modules: &[crate::guest::ModuleInfo]) -> LinuxState {
    use crate::guest::{find_module, linux as lx};
    use x86::bits64::vmx;
    use x86::vmx::vmcs::guest;

    serial_println!();
    serial_println!("=== P7f: Linux kernel load ===");

    // ── Locate modules ───────────────────────────────────────────────────── //
    let kernel_mod = find_module(modules, "dom0-kernel")
        .expect("P7f: 'dom0-kernel' module not found — check limine.conf");
    let initrd_mod = find_module(modules, "dom0-initrd");
    if initrd_mod.is_none() {
        serial_println!("  (no dom0-initrd module)");
    }

    // ── Strip DMAR + TPM2 from ACPI tables exposed to dom0 ─────────────── //
    // Write stripped RSDP + XSDT copies into dom0 memory so Linux never
    // discovers VT-d hardware or the TPM (capavisor-exclusive devices).
    // Falls back to 0 (Linux scans for RSDP) if there are no tables to
    // strip or the platform uses ACPI 1.0.
    let acpi_rsdp_addr =
        crate::arch::acpi::strip_dmar(info.acpi.rsdp_phys, lx::ACPI_COPY_PHYS, info.hhdm_offset)
            .unwrap_or(0);

    // ── Load kernel + initrd, write boot_params ──────────────────────────── //
    let load = lx::load_linux(
        kernel_mod,
        initrd_mod,
        info.hhdm_offset,
        &info.partition.dom0_owned[..info.partition.dom0_owned_count],
        &info.partition.meta_regions[..info.partition.meta_count],
        &info.partition.comm_region,
        &info.non_ram_e820,
        acpi_rsdp_addr,
        // intel_iommu=off kept as belt-and-suspenders in case DMAR stripping
        // is incomplete; can be removed once P7f-dmar is fully verified.
        // systemd.mask=boot-efi.mount: the EFI partition (vda15) fails because
        // the custom kernel lacks NLS iso8859-1; masking it avoids emergency mode.
        // Disk ordering: vda=ubuntu root disk, vdb=bins.img (RO artifact disk).
        "console=ttyS0,115200 earlyprintk=serial,ttyS0,115200 keep_bootcon intel_iommu=off nokaslr nopv root=/dev/vda1 rw loglevel=8 ignore_loglevel systemd.mask=boot-efi.mount systemd.mask=multipathd.service systemd.mask=systemd-networkd-wait-online.service",
    );

    // ── Patch VMCS guest RIP and RSP ─────────────────────────────────────── //
    // The VMCS for the BSP VP is still loaded (VMPTRLD'd) from P2d.
    // RSI (boot_params address) is a GPR — it cannot be vmwrite'd; P7g sets it
    // in the inline asm immediately before VMLAUNCH.
    unsafe {
        vmx::vmwrite(guest::RIP, load.kernel_entry_phys).expect("P7f: vmwrite guest RIP");
        vmx::vmwrite(guest::RSP, lx::INITIAL_RSP_PHYS).expect("P7f: vmwrite guest RSP");
    }

    serial_println!(
        "  VMCS patched: RIP={:#x} RSP={:#x}  (RSI={:#x} set at VMLAUNCH)",
        load.kernel_entry_phys,
        lx::INITIAL_RSP_PHYS,
        load.boot_params_phys,
    );
    serial_println!("=== P7f: done ===");

    LinuxState {
        kernel_entry_phys: load.kernel_entry_phys,
        boot_params_phys: load.boot_params_phys,
    }
}
