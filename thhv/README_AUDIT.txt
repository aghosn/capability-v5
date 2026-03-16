================================================================================
THHV DRIVER AUDIT — COMPLETE ANALYSIS FOR IRQFD/IOEVENTFD IMPLEMENTATION
================================================================================

AUDIT LOCATION: /home/aghosn/Documents/Programs/capability-v5/thhv/

DOCUMENTATION FILES GENERATED:
==============================

1. AUDIT.md (731 lines, 25 KB)
   Primary comprehensive reference covering all 10 audit requirements.
   Contains full struct definitions, code snippets, line numbers, and
   detailed status of all driver components.
   
   Best for: Technical deep-dive, implementation reference, full context

2. QUICK_REF.txt (156 lines, 8 KB)
   Visual summary with organized sections for rapid orientation.
   Lists key file locations, data structures, VMCALL infrastructure,
   DomainComm details, interrupt gaps, and implementation roadmap.
   
   Best for: Quick overview, planning, refresher

3. CODE_LOCATIONS.txt (312 lines, 14 KB)
   Pinpoint reference with exact line numbers and code excerpts.
   Organized by feature/component with file:line references.
   
   Best for: Code lookups, exact line number searches, implementation

4. AUDIT_INDEX.md (295 lines, 11 KB)
   Navigation document with quick answers to each of 10 requirements.
   Links between documents, implementation strategy, statistics.
   
   Best for: Finding specific information, planning, cross-references

================================================================================
WHAT THIS AUDIT COVERS (10 REQUIREMENTS)
================================================================================

1. Overall Driver Structure
   ✓ 7 source files analyzed (thhv.h, thhv_main.c, thhv_part.c, thhv_vp.c,
     thhv_hvcall.c, thhv_domcomm.c, thhv_translate.c)
   ✓ Purpose of each file documented
   ✓ File hierarchy and ioctl dispatch flow shown

2. Partition and VP Data Structures
   ✓ struct thhv_partition — 12 fields with full explanation
   ✓ struct thhv_vp — 13 fields with full explanation
   ✓ irqfds list, ioeventfds struct tracked in partition
   ✓ exit_wq and exit_pending in VP for async mode

3. DomainComm Integration
   ✓ Ring discovery via CPUID 0x40000002
   ✓ RX/TX ring enqueue/dequeue fully implemented
   ✓ Ring growth mechanism documented
   ✓ IPI handler status: MISSING (critical gap)
   ✓ Polling thread status: MISSING (critical gap)

4. VP Exit Handling
   ✓ Sync mode: themis_switch() works end-to-end
   ✓ Async mode: Incomplete (TODO at thhv_vp.c:88)
   ✓ Message reading from COMM page + 512 (256 bytes)
   ✓ Missing: IPI→exit_pending→exit_wq wakeup path

5. IRQFD Stub (P15g)
   ✓ Located at thhv_part.c:691-693 (currently -ENOSYS)
   ✓ struct thhv_irqfd defined (thhv.h:712-715)
   ✓ IOCTL macro: _IOW(0xB8, 0x13, struct thhv_irqfd)
   ✓ Partition tracking: part->irqfds list + mutex

6. IOEVENTFD Stub (P15h)
   ✓ Located at thhv_part.c:695-697 (currently -ENOSYS)
   ✓ struct thhv_ioeventfd defined (thhv.h:716-721)
   ✓ IOCTL macro: _IOW(0xB8, 0x14, struct thhv_ioeventfd)
   ✓ Partition tracking: part->ioeventfds.list + mutex

7. VMCALL Wrappers
   ✓ Raw primitive __themis_vmcall() documented (inline asm, register convention)
   ✓ 16 available wrappers catalogued (carve, send, switch, etc.)
   ✓ Missing wrappers identified (assert_interrupt, register_doorbell, etc.)
   ✓ Register convention explained (RAX=opcode, RDI/RSI/RDX/RCX/R8=args)

8. Interrupt Infrastructure
   ✓ THHV_SET_INTR_POLICY ioctl implemented (thhv_part.c:652)
   ✓ Visibility modes defined (DELIVER, REPORT, NOT_REPORT)
   ✓ Missing: SET_THEMIC_VECTOR call (critical gap)
   ✓ Missing: IDT handler registration (critical gap)
   ✓ Missing: IPI/notify mechanism (critical gap)

9. thhv.h Definitions
   ✓ struct thhv_irqfd: fd, gsi, flags, rsvd (16 bytes)
   ✓ struct thhv_ioeventfd: fd, flags, addr, len, datamatch (24 bytes)
   ✓ IOCTL macros with magic/command/direction
   ✓ All constants and definitions documented

10. Existing eventfd/workqueue Infrastructure
    ✓ EventFD support: NONE (no imports, no eventfd_ctx, no signals)
    ✓ Workqueue support: NONE (no create_workqueue, no queue_work)
    ✓ Waitqueue support: PARTIAL (exit_wq declared, not wired)
    ✓ Lists initialized: part->irqfds, part->ioeventfds (ready to use)

================================================================================
KEY FINDINGS
================================================================================

CRITICAL GAPS BLOCKING IMPLEMENTATION:
1. Async VP exit path incomplete (exit_pending/exit_wq never signaled)
2. No interrupt/IPI handler (notify_vector not configured)
3. No DomainComm RX polling thread (only manual dequeue)
4. No eventfd_ctx infrastructure (not imported or used)
5. Missing VMCALL wrappers (assert_interrupt, register_doorbell opcodes TBD)

DATA STRUCTURES READY FOR USE:
✓ partition->irqfds list + irqfd_lock (initialized)
✓ partition->ioeventfds.list + ioeventfds.lock (initialized)
✓ vp->exit_wq + vp->exit_pending (declared, needs wiring)
✓ IRQFD/IOEVENTFD struct definitions complete
✓ IOCTL dispatch stubs exist (return -ENOSYS)

VMCALL READINESS:
✓ Raw __themis_vmcall primitive works (tested in sync mode)
✓ 16 wrapper functions available and working
✓ Register convention documented
✓ Error mapping defined (__themis_to_errno)
✗ Custom opcodes need definition (assert_interrupt, register_doorbell)

DOMAINCOMM READINESS:
✓ Global state initialized (thhv_domcomm)
✓ Ring discovery working (CPUID 0x40000002)
✓ RX/TX enqueue/dequeue fully functional
✓ Ring growth mechanism complete
✗ No polling infrastructure
✗ No IPI notification system

================================================================================
HOW TO USE THESE DOCUMENTS
================================================================================

FOR QUICK ORIENTATION:
1. Read QUICK_REF.txt (5-10 minutes)
2. Review AUDIT_INDEX.md (5-10 minutes)
3. You now have the big picture

FOR IMPLEMENTATION:
1. Use CODE_LOCATIONS.txt as your primary reference
2. Look up exact line numbers and file paths
3. Copy code snippets as starting points
4. Refer to AUDIT.md for detailed context when needed

FOR DEEP UNDERSTANDING:
1. Start with AUDIT_INDEX.md section "Quick Answers" (10 min)
2. Read AUDIT.md section by section (30+ min)
3. All struct fields explained
4. All gaps clearly marked
5. Implementation implications discussed

FOR PLANNING:
1. See AUDIT_INDEX.md "Implementation Strategy"
2. Review critical path for IRQFD (8 steps)
3. Review critical path for IOEVENTFD (8 steps)
4. Common infrastructure checklist (5 items)

================================================================================
CRITICAL CODE LOCATIONS
================================================================================

IRQFD STUB:           thhv_part.c:691-693
IOEVENTFD STUB:       thhv_part.c:695-697
VMCALL PRIMITIVE:     inc/thhv.h:165-180
PARTITION STRUCT:     inc/thhv.h:910 (12 fields)
VP STRUCT:            inc/thhv.h:935 (13 fields)
DOMAINCOMM INIT:      thhv_domcomm.c:495
DOMAINCOMM RX:        thhv_domcomm.c:103
DOMAINCOMM TX:        thhv_domcomm.c:171
SYNC VP RUN:          thhv_vp.c:52-79
ASYNC VP RUN:         thhv_vp.c:81-99 (INCOMPLETE)
RUN_VP DISPATCH:      thhv_vp.c:38
SET_INTR_POLICY:      thhv_part.c:652

================================================================================
DOCUMENT STATISTICS
================================================================================

Source Files Analyzed:        7 (.c) + 1 (.h) = 8 total
Total Lines of Code Audited:  ~3,500 lines
Documentation Generated:      1,494 lines across 4 files
Code Snippets Included:       150+
Line-number References:       300+
Struct Definitions (complete): 6
VMCALL Wrappers Catalogued:   16 (available) + 3 (missing)
Critical Infrastructure Gaps: 5 identified
Ready-to-use Components:      5+ (lists, structs, IOCTL stubs)

================================================================================
NEXT STEPS FOR IMPLEMENTATION
================================================================================

BEFORE CODING:
1. Review QUICK_REF.txt (understand big picture)
2. Study AUDIT_INDEX.md "Implementation Strategy"
3. Read relevant sections of AUDIT.md for deep context

DURING CODING:
1. Use CODE_LOCATIONS.txt as your main reference
2. Keep AUDIT_INDEX.md open for cross-references
3. Refer back to AUDIT.md for struct field definitions

CRITICAL PATH - IRQFD (P15g):
1. Create thhv_irqfd_entry struct (wrap eventfd_ctx + GSI)
2. Implement thhv_irqfd_add() (validate, get context, link list)
3. Implement GSI→entry lookup (hash table or binary search)
4. Create themis_assert_interrupt wrapper (custom opcode)
5. Wire DomainComm RX: DOMCOMM_MSG_IRQ_NOTIFY → eventfd_signal()
6. Complete async VP exit (IPI → exit_pending → exit_wq)
7. Implement thhv_irqfd_del() (deassign, cleanup)
8. Add cleanup in thhv_partition_destroy()

CRITICAL PATH - IOEVENTFD (P15h):
1. Create thhv_ioeventfd_entry struct (wrap eventfd_ctx + addr + len)
2. Implement thhv_ioeventfd_add() (validate, get context, link list)
3. Implement addr-based lookup (interval tree or hash table)
4. Create themis_register_doorbell wrapper (opcode 0x15)
5. Wire guest write detection: doorbell → eventfd_signal()
6. Support optional datamatch filtering
7. Implement thhv_ioeventfd_del() (deassign, cleanup)
8. Add cleanup in thhv_partition_destroy()

COMMON INFRASTRUCTURE (required for both):
1. DomainComm RX polling (thread or work queue)
2. notify_vector interrupt handler registration
3. SET_THEMIC_VECTOR VMCALL on partition creation
4. Complete async VP exit path (exit_pending flag, wakeup logic)
5. Add eventfd cleanup in thhv_partition_destroy() (TODO line 92)

================================================================================
