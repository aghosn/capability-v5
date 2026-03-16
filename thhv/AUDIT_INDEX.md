# THHV Driver Audit — Complete Documentation Index

## 📋 Overview

This audit provides a **comprehensive analysis** of the thhv Linux kernel driver at `/home/aghosn/Documents/Programs/capability-v5/thhv/` to establish a foundation for implementing **IRQFD (P15g)** and **IOEVENTFD (P15h)** support.

**Audit Date**: March 2025  
**Scope**: All 6 source files + 1 main header, focusing on:
- Overall driver architecture
- Partition and VP data structures  
- DomainComm ring integration
- VP exit handling (sync & async modes)
- IRQFD/IOEVENTFD stubs and surrounding context
- Themis VMCALL infrastructure
- Interrupt configuration and handler status
- Existing eventfd/workqueue infrastructure

---

## 📚 Audit Documents

### 1. **AUDIT.md** (25 KB, 731 lines)
**Comprehensive technical reference** covering all 10 audit requirements with detailed code snippets and line numbers.

**Contents**:
1. Overall driver structure (7 source files with descriptions)
2. Partition struct (full definition with field-by-field explanation)
3. VP struct (full definition and async mode status)
4. DomainComm integration (initialization, RX/TX, ring growth, polling status)
5. VP exit handling (sync mode working, async mode incomplete with TODO locations)
6. IRQFD stub (current code at thhv_part.c:691, structure definition, macro)
7. IOEVENTFD stub (current code at thhv_part.c:695, structure definition, macro)
8. VMCALL wrappers (raw primitive, available wrappers, missing wrappers)
9. Interrupt infrastructure (policy setup, notify_vector status, ThemIC structures)
10. EventFD and workqueue infrastructure (none for eventfd, partial for async)

**Best for**: Deep technical understanding, detailed implementation reference

---

### 2. **CODE_LOCATIONS.txt** (14 KB)
**Pinpoint reference** for all critical code locations with exact line numbers and code excerpts.

**Contents**:
- 8 major sections with file:line references
- IRQFD stub (thhv_part.c:691) with surrounding context
- IOEVENTFD stub (thhv_part.c:695) with surrounding context
- VMCALL primitive and wrappers (inc/thhv.h:165-180, thhv_hvcall.c)
- DomainComm structures and functions
- VP exit handling (both sync and async paths)
- Interrupt infrastructure status
- Full struct definitions (thhv_partition, thhv_vp)
- Function call paths for IRQFD/IOEVENTFD registration

**Best for**: Quick code lookups, implementing specific features

---

### 3. **QUICK_REF.txt** (8 KB)
**Visual summary** with organized sections for rapid orientation.

**Contents**:
- Key file locations (6 critical points)
- Data structures (4 main structs with field annotations)
- VMCALL infrastructure (available/missing wrappers, raw primitive)
- DomainComm ring infrastructure (state, message types, functions)
- Interrupt infrastructure gaps (✅ done, ❌ not done)
- Implementation roadmap for IRQFD/IOEVENTFD
- Struct sizes

**Best for**: Overview, planning implementation strategy

---

## 🎯 Quick Answers to Audit Requirements

### 1. **Overall Driver Structure**
**File**: AUDIT.md (Section 1), CODE_LOCATIONS.txt (Section 3)

7 source files:
- **thhv.h**: Main UAPI header (ioctl defs, structs, Themis opcodes, DomainComm, ThemIC)
- **thhv_main.c**: Module init, CPUID detection, /dev/thhv character device
- **thhv_part.c**: Partition lifecycle, memory mapping, ioctl dispatch
- **thhv_vp.c**: VP lifecycle, pin pages, VP exit (sync working, async incomplete)
- **thhv_hvcall.c**: Themis hypercall wrappers (16 functions, using __themis_vmcall)
- **thhv_domcomm.c**: DomainComm ring (init, rx_dequeue, tx_enqueue, grow)
- **thhv_translate.c**: GPA→HPA translation (not shown but referenced)

---

### 2. **Partition and VP Data Structures**
**File**: AUDIT.md (Section 2), CODE_LOCATIONS.txt (Section 7)

**struct thhv_partition** (inc/thhv.h ~910):
- 12 fields: domain_handle, sched_policy, vps array, META pages, memory region tree, sent_caps list, **irqfds list**, **ioeventfds struct**, file, refcount

**struct thhv_vp** (inc/thhv.h ~935):
- 13 fields: vp_index, partition ptr, run_lock, **exit_wq**, **exit_pending**, exit_msg buffer, META pages, COMM page (mapped, HPA, handles), comm_registered flag, file

Both structures shown with **full field-by-field explanation** and purpose.

---

### 3. **DomainComm Integration**
**File**: AUDIT.md (Section 3), CODE_LOCATIONS.txt (Section 4)

✅ **Working**:
- CPUID 0x40000002 discovery (thhv_domcomm.c:504)
- Global thhv_domcomm state initialized (domcomm_init, thhv_main.c:177)
- RX/TX ring enqueue/dequeue (fully implemented, safe for multi-page messages)
- Ring growth mechanism (alloc, CARVE, REGISTER_COMM, TX/RX handshake)

❌ **NOT WORKING**:
- No interrupt/IPI handler for notify_vector
- No polling thread; RX only drained on demand (domcomm_request_grow)
- Async VP exit path incomplete (TODO at thhv_vp.c:88)

---

### 4. **VP Exit Handling**
**File**: AUDIT.md (Section 4), CODE_LOCATIONS.txt (Section 5)

**Sync Mode (WORKS)**:
- themis_switch() blocks caller until child VP exits
- On ERR_RETRY (physical interrupt), retries after checking signals
- Reads intercept message from COMM page + 512 (256 bytes)
- Returns via copy_to_user

**Async Mode (INCOMPLETE)**:
- Declared: wait_event_interruptible(exit_wq, exit_pending)
- **Missing**: No code sets exit_pending or calls wake_up()
- **Missing**: No IPI handler or DomainComm polling

---

### 5. **IRQFD Stub (P15g)**
**File**: CODE_LOCATIONS.txt (Section 1), AUDIT.md (Section 5)

**Location**: thhv_part.c:691-693
```c
case THHV_IRQFD:
    /* TODO(P15g): eventfd → VMCALL_ASSERT_INTERRUPT */
    return -ENOSYS;
```

**Structure**: thhv.h:712-715 (16 bytes: fd, gsi, flags, rsvd)
**IOCTL macro**: thhv.h:814-815 (_IOW 0xB8/0x13)
**Tracking**: partition->irqfds list + partition->irqfd_lock (initialized at thhv_part.c:760-761)

---

### 6. **IOEVENTFD Stub (P15h)**
**File**: CODE_LOCATIONS.txt (Section 2), AUDIT.md (Section 6)

**Location**: thhv_part.c:695-697
```c
case THHV_IOEVENTFD:
    /* TODO(P15h): VMCALL_REGISTER_DOORBELL */
    return -ENOSYS;
```

**Structure**: thhv.h:716-721 (24 bytes: fd, flags, addr, len, datamatch)
**IOCTL macro**: thhv.h:817-818 (_IOW 0xB8/0x14)
**Tracking**: partition->ioeventfds.list + partition->ioeventfds.lock (initialized at thhv_part.c:763-764)

---

### 7. **VMCALL Wrappers**
**File**: CODE_LOCATIONS.txt (Section 3), AUDIT.md (Section 7)

**Raw VMCALL Primitive** (inc/thhv.h:165-180):
```c
__themis_vmcall(opcode, a0, a1, a2, a3, a4, r0, r1, r2)
```
Register convention: RAX=opcode, RDI/RSI/RDX/RCX/R8 = args, returns in RAX/RDI/RSI/RDX

**Available Wrappers** (thhv_hvcall.c, 16 total):
- Memory: themis_carve, themis_alias, themis_send, themis_revoke_mem
- Domain: themis_create_domain, themis_seal, themis_switch, themis_revoke_domain
- Attestation: themis_attest_self, themis_attest, themis_get_chan
- VP: themis_get_reg, themis_set_reg, themis_add_vp
- Interrupt: themis_set_intr_policy, themis_set_def_intr_policy
- Device: themis_assign_device
- DomainComm: themis_register_comm, themis_domcomm_notify

**Missing Wrappers** (needed for IRQFD/IOEVENTFD):
- themis_set_themic_vector (0x17) — NOT WRAPPED
- themis_register_doorbell (0x15) — NOT WRAPPED
- themis_assert_interrupt — OPCODE NOT DEFINED

---

### 8. **Interrupt Infrastructure**
**File**: CODE_LOCATIONS.txt (Section 6), AUDIT.md (Section 8)

**Status**: ⚠️ MINIMAL (policy setup only, no handler/IPI)

✅ **Done**:
- THHV_SET_INTR_POLICY ioctl (thhv_part.c:652)
- Visibility modes defined (DELIVER/REPORT/NOT_REPORT)
- themis_set_intr_policy wrapper exists

❌ **NOT DONE**:
- No SET_THEMIC_VECTOR call (notify_vector never configured)
- No IDT interrupt handler registered
- No IPI mechanism
- Async mode completely unimplemented
- No DomainComm RX polling

---

### 9. **thhv.h Definitions**
**File**: CODE_LOCATIONS.txt (Section 1-2), AUDIT.md (Section 9)

**struct thhv_irqfd** (thhv.h:712-715): 4 fields, 16 bytes
**struct thhv_ioeventfd** (thhv.h:716-721): 5 fields, 24 bytes
**THHV_IRQFD macro** (thhv.h:814-815): _IOW(0xB8, 0x13, struct thhv_irqfd)
**THHV_IOEVENTFD macro** (thhv.h:817-818): _IOW(0xB8, 0x14, struct thhv_ioeventfd)

---

### 10. **EventFD and Workqueue Infrastructure**
**File**: AUDIT.md (Section 10)

**EventFD Support**: ❌ **NONE**
- No eventfd.h imports
- No eventfd_ctx_get/put
- No eventfd_signal calls
- No poll handlers

**Workqueue Support**: ❌ **NONE**
- No workqueue creation
- No queue_work calls
- No background threads

**Waitqueue Usage**: ⚠️ **PARTIAL (Async Mode Only)**
- vp->exit_wq + vp->exit_pending declared
- Initialized at thhv_vp.c:473-474
- Wait at thhv_vp.c:91-92
- **Missing**: wake_up() calls

**Partition Lists**: ✅ **Declared but Unused**
- part->irqfds + part->irqfd_lock (initialized)
- part->ioeventfds.list + part->ioeventfds.lock (initialized)
- Both marked TODO for cleanup at thhv_part.c:92

---

## 🛠️ Implementation Strategy

### Critical Path for IRQFD (P15g):
1. Create thhv_irqfd_entry struct (wrap eventfd_ctx + GSI)
2. Implement thhv_irqfd_add() — validate, get eventfd_ctx, link to partition->irqfds
3. Implement GSI → entry lookup (hash table or binary search)
4. Create themis_assert_interrupt wrapper (custom opcode + vmcall)
5. Wire DomainComm RX: DOMCOMM_MSG_IRQ_NOTIFY → eventfd_signal()
6. Complete async VP exit path (IPI → exit_pending → exit_wq wake)

### Critical Path for IOEVENTFD (P15h):
1. Create thhv_ioeventfd_entry struct (wrap eventfd_ctx + addr + len)
2. Implement thhv_ioeventfd_add() — validate, get eventfd_ctx, link to partition->ioeventfds
3. Implement addr-based lookup (interval tree or hash table)
4. Create themis_register_doorbell wrapper (opcode 0x15)
5. Wire guest write detection: doorbell write → eventfd_signal()
6. Support optional datamatch filtering

### Common Infrastructure:
1. DomainComm RX polling thread or work queue
2. notify_vector interrupt handler registration
3. SET_THEMIC_VECTOR vmcall on partition creation
4. Complete async VP exit path
5. Eventfd cleanup in thhv_partition_destroy()

---

## 📊 Document Statistics

| Document | Size | Lines | Best For |
|----------|------|-------|----------|
| AUDIT.md | 25 KB | 731 | Technical reference, full context |
| CODE_LOCATIONS.txt | 14 KB | 350+ | Code lookups, exact line numbers |
| QUICK_REF.txt | 8 KB | 180+ | Overview, planning, quick answers |

---

## 🔗 Related Documentation

- **docs/domain-comm-v0.2.md**: DomainComm protocol specification
- **README.md**: Driver overview and usage
- **Themis ABI documentation**: (external, referenced in code)

---

**Generated**: March 2025  
**Status**: Complete and ready for implementation
