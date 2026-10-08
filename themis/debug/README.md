# Linux instrumentation for the dom1 handoff

`linux-instrumentation.patch` captures the 18 modified files in the external
Linux checkout on October 8, 2026. It is a plain Git diff, not a `git am`
mailbox. No Linux branch or commit was created.

Apply it to Linux commit:

```text
44df971c640f8618de24aa08a9019496353e1b47
```

The source checkout on the old machine is
`/home/aghosn/Documents/Programs/linux`, branch `v6.19.14-themis`.
The patch includes all tracked changes relative to that commit; it does not
include the kernel configuration, modules or built images.

Validation used an isolated Git index at the base commit: the patch applied
cleanly and the resulting files exactly matched the instrumented working
tree. The original Linux index and files were not modified.

## Apply on the new machine

Start with a clean Linux checkout at the commit above. Do not apply this over
the already-instrumented old checkout or unrelated local modifications.

```sh
cd /path/to/linux
git status --short
git rev-parse HEAD

PATCH=/path/to/capability-v5/themis/debug/linux-instrumentation.patch
git apply --check "$PATCH"
git apply "$PATCH"
```

To reproduce the build configuration, extract `cleanup/linux.config` from
the separately transferred `themis-dom1-evidence-2026-10-08.tar.gz`:

```sh
cp /path/to/extracted-evidence/cleanup/linux.config .config
make olddefconfig
make -j4 bzImage modules
```

These commands do not install the kernel or replace Themis's packaged guest
image. Transfer/package the matching kernel and modules explicitly if changing
the boot baseline. The original instrumented source compiled successfully
with `make -j4 bzImage modules`; this does not establish successful dom1 boot.

## Scope and debug behavior

The patch instruments init/exec, APIC interrupts, cgroup/kernfs, percpu-rwsem,
RCU, idle and timer paths. It is diagnostic code for a **Themis guest**, not
a kernel change required on the native Linux host.

The guest `themis_trace_enabled` flag gates trace VMCALLs. The current patch
enables that flag at init launch and issues a VMCALL to enable capavisor
runtime logging. Disabling logging with dom0's `toggle-debug 0` afterward
only suppresses serial output; it does not clear the guest flag or eliminate
the VMCALL overhead. Instrumentation can affect timing.

See `docs/dom1-debugging-handoff.md` at repository root for the observations,
separate log controls, reproduction procedure and unresolved limitations.
