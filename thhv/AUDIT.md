# THHV Linux Kernel Driver — Comprehensive Audit

**Location**: `/home/aghosn/Documents/Programs/capability-v5/thhv/`

---

## 1. Overall Driver Structure

### Source Files (inc/ + src/)

| File | Purpose |
|------|---------|
| **inc/thhv.h** | Main UAPI header: ioctl definitions, struct definitions (partition, vp, irqfd, ioeventfd), Themis hypercall constants, DomainComm types, ThemIC message structures |
| **src/thhv_main.c** | Module init/exit, CPUID detection, /dev/thhv character device registration, device-level ioctl dispatch |
| **src/thhv_part.c** | Partition fd lifecycle: creation, cleanup, memory mapping (THHV_SET_GUEST_MEMORY), ioctl dispatch, irqfd/ioeventfd list initialization |
| **src/thhv_vp.c** | VP fd lifecycle: creation, pinning pages, VP exit handling (thhv_run_vp), register get/set, COMM page management |
| **src/thhv_hvcall.c** | Themis hypercall wrappers: themis_carve(), themis_send(), themis_switch(), themis_set_intr_policy(), themis_register_comm(), themis_add_vp(), themis_domcomm_notify(), etc. Uses __themis_vmcall() primitive |
| **src/thhv_domcomm.c** | DomainComm ring management: CPUID discovery, rx_dequeue, tx_enqueue, ring growth (grow_rx/grow_tx), initialization |
| **src/thhv_translate.c** | GPA→HPA translation, PA map initialization from attestation |

### File Hierarchy (User-facing)

```
/dev/thhv (device fd)
  ├─ THHV_CREATE_PARTITION → partition fd
  │   ├─ THHV_CREATE_VP → vp fd
  │   ├─ THHV_SET_GUEST_MEMORY
  │   ├─ THHV_IRQFD (stub: -ENOSYS)
  │   ├─ THHV_IOEVENTFD (stub: -ENOSYS)
  │   ├─ THHV_SEND_SHARED_META
  │   └─ THHV_INITIALIZE_PARTITION
  │
  └─ THHV_CHECK_EXTENSION
  └─ THHV_QUERY
```

---

## 2. Partition and VP Data Structures

### struct thhv_partition (inc/thhv.h, lines ~910)

```c
struct thhv_partition {
    u64 domain_handle;                    /* Handle to Themis domain */
    u64 domain_id;
    u32 sched_policy;                     /* THHV_SCHED_SYNC or THHV_SCHED_ASYNC */
    u32 num_vps;
    bool sealed;                          /* INITIALIZE_PARTITION called */

    struct thhv_vp **vps;                 /* Array of VPs (lazily populated) */

    /* Shared META pages: MSR bitmap + IO bitmaps A & B (pinned at INITIALIZE) */
    struct page **shared_meta_pages;
    unsigned int  shared_meta_nr_pages;

    /* EPT META pages: kernel-allocated, sent to child for EPT page tables */
    struct page **ept_meta_pages;
    unsigned int  ept_meta_nr_pages;

    /* Memory region tracking: guest_pfn → pinned pages (for unpin on cleanup) */
    struct {
        spinlock_t lock;
        struct rb_root regions;           /* rb-tree of thhv_mem_region */
    } mem;

    /* Capabilities sent to this child domain (for revocation on teardown) */
    struct {
        spinlock_t lock;
        struct list_head list;            /* list of thhv_sent_cap */
    } sent_caps;

    /* IRQfd tracking */
    struct list_head irqfds;              /* TODO(P15g): implement */
    struct mutex irqfd_lock;

    /* IOEventFd / doorbell tracking */
    struct {
        struct list_head list;            /* TODO(P15h): implement */
        struct mutex lock;
    } ioeventfds;

    struct file *file;
    struct kref refcount;
};
```

**Fields Summary**:
- **domain_handle**: Opaque Themis capability returned by THEMIS_OP_CREATE_DOMAIN
- **sched_policy**: Determines if VP runs synchronously (parent blocks in themis_switch) or asynchronously (capavisor sends VP_EXIT via DomainComm)
- **sealed**: Becomes true after INITIALIZE_PARTITION / themis_seal() is called
- **vps**: Dynamically allocated array; entries created by THHV_CREATE_VP
- **shared_meta_pages / ept_meta_pages**: Required for capavisor VMCS/VAPIC allocation
- **mem.regions**: Red-black tree of guest memory mappings (for cleanup)
- **sent_caps.list**: Capabilities (carved/aliased pages) sent to child via THEMIS_OP_SEND (revoked on partition teardown)
- **irqfds / ioeventfds**: Unimplemented (currently return -ENOSYS)

---

### struct thhv_vp (inc/thhv.h, lines ~935)

```c
struct thhv_vp {
    u32 vp_index;
    struct thhv_partition *partition;
    struct mutex run_lock;                /* Serializes THHV_RUN_VP calls */

    /* Async mode waitqueue */
    wait_queue_head_t exit_wq;
    atomic_t exit_pending;                /* Set by IPI handler when VP exits (TODO) */

    /* Exit info buffer for userspace */
    u8 exit_msg[256];                     /* ThemIC intercept message (copied from COMM page) */

    /* META pages: pinned from userspace, for capavisor internal alloc (VMCS + VAPIC) */
    struct page **meta_pages;
    unsigned int  meta_nr_pages;          /* Should be THHV_META_PAGES_PER_VP (3) */

    /* COMM page: pinned from userspace, shared with capavisor */
    struct page  *comm_page;
    void         *comm_kaddr;             /* Kernel VA of mapped COMM page */
    u64           comm_phys;              /* HPA (after GPA→HPA translation) */
    u64           comm_parent_handle;     /* Parent cap used for CARVE */
    u64           comm_cap_handle;        /* Carved child handle for COMM cap */
    u64           comm_cap_sub;           /* Sub-handle for REVOKE(parent, sub) */
    bool          comm_registered;        /* REGISTER_COMM done (ADD_VP called) */

    struct file *file;
};
```

**Fields Summary**:
- **run_lock**: Prevents concurrent THHV_RUN_VP calls on the same VP
- **exit_wq / exit_pending**: For async mode; currently incomplete (TODO in thhv_vp.c:88)
- **exit_msg**: Buffer to hold ThemIC intercept message on return from RUN_VP
- **meta_pages / comm_page**: User-pinned pages sent to capavisor
- **comm_kaddr**: Kernel mapping of comm_page (used by thhv_run_vp to read intercept message)
- **comm_registered**: Tracks if ADD_VP vmcall has been issued (required before RUN_VP)

---

## 3. DomainComm Integration

### DomainComm Overview (thhv_domcomm.c)

DomainComm is a **bidirectional message ring** between dom0 (driver) and capavisor:
- **RX ring**: Capavisor → dom0 (VP exits in async mode, attestation data, grow acks)
- **TX ring**: dom0 → Capavisor (grow requests, enumeration requests, ACKs)
- **Discovery**: CPUID leaf 0x40000002 returns GPA and page count
- **Message format**: 16-byte header (type, total_size, sequence) + payload
- **Page boundary**: Messages never cross page boundaries; padding (DOMCOMM_MSG_NONE) fills gaps

### struct domcomm_state (inc/thhv.h, lines ~1021)

```c
struct domcomm_state {
    void __iomem         *base;           /* memremap'd header page */
    struct domcomm_header *hdr;           /* = base, typed access to header */
    struct domcomm_ring   rx;             /* RX ring: capavisor → domain (we consume) */
    struct domcomm_ring   tx;             /* TX ring: domain → capavisor (we produce) */
    u64                   gpa;            /* GPA of the DomainComm region (from CPUID) */
    unsigned int          total_pages;
    bool                  initialized;
    u64                   self_domain_handle;  /* For REGISTER_COMM self-ref */
};

extern struct domcomm_state thhv_domcomm;  /* Global instance */
```

### struct domcomm_ring (inc/thhv.h, lines ~1010)

```c
struct domcomm_ring {
    void __iomem **page_vas;              /* Array of per-page virtual addresses */
    unsigned int   nr_pages;              /* Number of backing pages */
    __u32         *head;                  /* Pointer to head in header page */
    __u32         *tail;                  /* Pointer to tail in header page */
    u32            capacity;              /* Total ring size in bytes (nr_pages * PAGE_SIZE) */
    u64            next_seq;              /* Next sequence number to use (producer) */
};
```

### DomainComm Initialization (thhv_domcomm.c:495)

**domcomm_init()** called from thhv_main.c during module init:
1. **Line 504**: `cpuid(THHV_CPUID_DOMCOMM_LEAF, ...)` retrieves GPA (EAX:EBX) and page count (ECX)
2. **Line 520**: `memremap(gpa, PAGE_SIZE, MEMREMAP_WB)` maps header page
3. **Line 531-544**: Validates magic (DOMCOMM_MAGIC = 0x444F4D43) and version
4. **Line 551-558**: Initializes RX and TX rings via domcomm_ring_init()
5. **Returns**: 0 on success, -ENODEV if no DomainComm region, -EINVAL/-ENOMEM on error

**domcomm_ring_init()** (thhv_domcomm.c:431):
- Maps all ring pages via memremap()
- Sets up head/tail pointers to header fields
- Returns -EINVAL if page indices out of range, -ENOMEM if memremap fails

### RX Ring Consumption (thhv_domcomm.c:103)

**domcomm_rx_dequeue(ring, buf, buf_size, &out_type, &out_payload_size)**:
- **Line 112**: Reads producer head with `smp_load_acquire()`
- **Line 115-116**: Returns -EAGAIN if ring empty (head == tail)
- **Line 121**: Peeks at message header
- **Line 124-135**: Skips padding messages (DOMCOMM_MSG_NONE) by advancing tail to next page
- **Line 143-145**: Returns -ENOSPC if payload exceeds buf_size
- **Line 148**: Reads payload after header
- **Line 154**: Advances tail with `smp_store_release()`

### TX Ring Production (thhv_domcomm.c:171)

**domcomm_tx_enqueue(ring, msg_type, payload, payload_size)**:
- **Line 178**: Aligns total_size to 8 bytes
- **Line 185-189**: Checks available space
- **Line 191-212**: Emits padding (DOMCOMM_MSG_NONE) if message doesn't fit in current page
- **Line 217-226**: Writes payload, then header
- **Line 229-230**: Issues wmb() and advances head with release semantics

### Ring Growth (thhv_domcomm.c:250)

**domcomm_request_grow(bool grow_rx, u32 nr_pages)**:
1. **Line 273-276**: Allocate physically contiguous pages via alloc_pages()
2. **Line 279-280**: Translate GPA → HPA via thhv_gpa_to_hpa()
3. **Line 290-291**: Find parent capability covering HPA range
4. **Line 301-304**: CARVE a new capability for growth pages
5. **Line 314-315**: Insert into local cap table
6. **Line 324-325**: REGISTER_COMM (self-ref, vp_id=0) to bind growth cap
7. **Line 339-342**: TX enqueue a GROW_RX or GROW_TX request
8. **Line 351**: VMCALL_DOMCOMM_NOTIFY to alert capavisor
9. **Line 360-365**: Dequeue GROW_ACK from RX ring
10. **Line 378-399**: Extend page_vas array and remap new pages

### Current IPI / Interrupt Handler Status

**NO interrupt handler or IPI infrastructure exists for notify_vector**.

- **thhv_vp.c:81-99**: Async mode is declared but incomplete (TODO at line 88)
  ```c
  } else {
      /* Async mode: [...] Park until an exit event arrives via the DomainComm
       * RX ring (capavisor enqueues DOMCOMM_MSG_VP_EXIT and
       * sends an IPI; the handler sets exit_pending and wakes us).
       *
       * TODO: Wire the DomainComm RX ring → IPI handler →
       * exit_pending path.  For now, park on the waitqueue.
       */
      ret = wait_event_interruptible(vp->exit_wq,
                                     atomic_read(&vp->exit_pending));
  ```
- **No SET_THEMIC_VECTOR call**: notify_vector is never configured
- **No DomainComm RX polling thread**: Currently only called on demand (domcomm_request_grow)
- **Drain mechanism**: Manual via domcomm_rx_dequeue() in application code

---

## 4. VP Exit Handling

### Sync Mode Exit (thhv_vp.c:52-79)

**thhv_run_vp()** in sync scheduling:
```c
do {
    ret = themis_switch(part->domain_handle, vp->vp_index);  // Line 65
    if (ret != -EAGAIN)
        break;
    if (signal_pending(current)) {                           // Line 68
        mutex_unlock(&vp->run_lock);
        return -EINTR;
    }
} while (true);

if (ret) {
    mutex_unlock(&vp->run_lock);
    return ret;
}

thhv_read_intercept_msg(vp, msg_buf);                       // Line 79
```

**Behavior**:
- Blocks caller thread in VMCALL SWITCH until child VP exits
- On ERR_RETRY (physical interrupt), retries after checking signals
- Reads intercept message from COMM page offset 512 (256 bytes)
- Returns message to userspace via copy_to_user

### Async Mode Exit (thhv_vp.c:81-99) — **INCOMPLETE**

```c
ret = wait_event_interruptible(vp->exit_wq,
                               atomic_read(&vp->exit_pending));
if (ret) {
    mutex_unlock(&vp->run_lock);
    return -EINTR;
}

atomic_set(&vp->exit_pending, 0);
thhv_read_intercept_msg(vp, msg_buf);
```

**Status**: 
- Parks thread on exit_wq until exit_pending is set to 1
- **Missing**: No code sets exit_pending on DOMCOMM_MSG_VP_EXIT reception
- **Missing**: No IPI handler wakes vp->exit_wq

### Intercept Message Reading (thhv_vp.c:30)

```c
static void thhv_read_intercept_msg(struct thhv_vp *vp, void *out_buf)
{
    /* Copy the intercept slot (256 bytes) from comm page offset 512. */
    memcpy(out_buf, (u8 *)vp->comm_kaddr + 512, THEMIC_MSG_SLOT_SIZE);
}
```

**Notes**:
- Reads from COMM page + 512 offset (padding area, transitional)
- Eventually should read from dedicated ThemIC message page slot 0
- ThemIC slot 0 = THEMIC_CHAN_INTERCEPT (VP exit/intercept messages)

---

## 5. IRQFD Stub (thhv_part.c:691)

### Current Implementation

**thhv_part.c:691-693**:
```c
case THHV_IRQFD:
    /* TODO(P15g): eventfd → VMCALL_ASSERT_INTERRUPT */
    return -ENOSYS;
```

**Location in ioctl dispatch**: thhv_part_ioctl() handles partition-level commands
- Called from partition fd ioctl handler
- No struct validation, no eventfd access

### Struct Definition (inc/thhv.h, lines ~712)

```c
struct thhv_irqfd {
    __s32 fd;          /* eventfd file descriptor */
    __u32 gsi;         /* Global System Interrupt (0-255 typically) */
    __u32 flags;       /* Control flags (deassign, resample, level) */
    __u32 rsvd;
};
```

### IOCTL Macro (inc/thhv.h, line ~814)

```c
#define THHV_IRQFD \
    _IOW(THHV_IOCTL_MAGIC, 0x13, struct thhv_irqfd)
```

- Magic: 0xB8
- Command: 0x13
- Direction: _IOW (write only)
- Size: sizeof(struct thhv_irqfd) = 16 bytes

### Infrastructure to Implement

**Needed vmcalls** (from thhv_hvcall.c available):
- None for IRQFD directly; custom VMCALL needed for asserting interrupts
- Likely: THEMIS_OP_SET_THEMIC_VECTOR (line 76 in thhv.h: 0x17) to configure notify vector
- Likely: Custom opcode for VMCALL_ASSERT_INTERRUPT (not in current wrapper list)

**Existing eventfd infrastructure in driver**: **NONE** (no eventfd_ctx usage, no poll handlers)

---

## 6. IOEVENTFD Stub (thhv_part.c:695)

### Current Implementation

**thhv_part.c:695-697**:
```c
case THHV_IOEVENTFD:
    /* TODO(P15h): VMCALL_REGISTER_DOORBELL */
    return -ENOSYS;
```

### Struct Definition (inc/thhv.h, lines ~716)

```c
struct thhv_ioeventfd {
    __s32 fd;          /* eventfd file descriptor */
    __u32 flags;       /* Control flags */
    __u64 addr;        /* Guest physical address (doorbell GPA) */
    __u32 len;         /* Doorbell region size (1, 2, 4) */
    __u32 datamatch;   /* Optional data pattern match */
};
```

### IOCTL Macro (inc/thhv.h, line ~817)

```c
#define THHV_IOEVENTFD \
    _IOW(THHV_IOCTL_MAGIC, 0x14, struct thhv_ioeventfd)
```

- Magic: 0xB8
- Command: 0x14
- Direction: _IOW (write only)
- Size: sizeof(struct thhv_ioeventfd) = 24 bytes

### Infrastructure Tracking

**In partition struct** (thhv_part.c:763-764):
```c
INIT_LIST_HEAD(&part->ioeventfds.list);
mutex_init(&part->ioeventfds.lock);
```

**In cleanup** (thhv_part.c:92):
```c
/* TODO: free irqfds, ioeventfds */
```

### Needed Vmcall

**THEMIS_OP_REGISTER_DOORBELL** (opcode 0x15, defined in thhv.h line 82):
- Not wrapped in thhv_hvcall.c (missing wrapper function)
- Takes: domain, doorbell address, eventfd config
- Configures ThemIC doorbell channel

---

## 7. VMCALL Wrappers

### Raw VMCALL Primitive (__themis_vmcall)

**inc/thhv.h, lines ~165-180** (inline asm):

```c
static inline u64 __themis_vmcall(u64 opcode,
                                  u64 a0, u64 a1, u64 a2, u64 a3, u64 a4,
                                  u64 *r0, u64 *r1, u64 *r2)
{
    u64 status, o0, o1, o2;
    register u64 _a4 asm("r8") = a4;

    asm volatile("vmcall"
        : "=a"(status), "=D"(o0), "=S"(o1), "=d"(o2)
        : "a"(opcode), "D"(a0), "S"(a1), "d"(a2),
          "c"(a3), "r"(_a4)
        : "r9", "r10", "r11", "memory", "cc"
    );

    if (r0) *r0 = o0;
    if (r1) *r1 = o1;
    if (r2) *r2 = o2;
    return status;
}
```

**Register Convention**:
- **IN**: RAX (opcode), RDI (a0), RSI (a1), RDX (a2), RCX (a3), R8 (a4)
- **OUT**: RAX (status), RDI (r0), RSI (r1), RDX (r2)

**Error Mapping** (__themis_to_errno, lines ~182-192):
```c
static inline int __themis_to_errno(u64 status)
{
    switch (status) {
    case THEMIS_SUCCESS:      return 0;
    case THEMIS_ERR_INVALID:  return -EINVAL;
    case THEMIS_ERR_NOPERM:   return -EPERM;
    case THEMIS_ERR_NOMEM:    return -ENOMEM;
    case THEMIS_ERR_BADSTATE: return -EBUSY;
    case THEMIS_ERR_NOTFOUND: return -ENOENT;
    case THEMIS_ERR_RETRY:    return -EAGAIN;
    case THEMIS_ERR_UNIMPL:   return -ENOSYS;
    default:                  return -EIO;
    }
}
```

### Available Themis Wrappers (thhv_hvcall.c)

**Memory Capability Operations**:
- `themis_carve()` (line 25): CARVE parent cap, return handle + sub
- `themis_alias()` (line 34): ALIAS for shared access
- `themis_send()` (line 43): SEND cap to receiver
- `themis_send_at()` (line 51): SEND with child GPA
- `themis_accept()` (line 59): ACCEPT pending capability
- `themis_reject()` (line 67): REJECT pending cap
- `themis_revoke_mem()` (line 75): REVOKE_MEM parent + sub

**Domain Operations**:
- `themis_create_domain()` (line 85): CREATE_DOMAIN with cores/flags/num_vps
- `themis_seal()` (line 94): SEAL domain (finalize config, allow execution)
- `themis_revoke_domain()` (line 102): REVOKE_DOMAIN recursively
- `themis_switch()` (line 110): SWITCH to target domain VP (sync mode run)

**Attestation**:
- `themis_get_chan()` (line 120): GET_CHAN for attestation data
- `themis_attest_self()` (line 128): ATTEST_SELF (dom0 to capavisor)
- `themis_attest()` (line 136): ATTEST child domain

**VP Register Access**:
- `themis_get_reg()` (line 146): GET_REG from VP (domain, vp_id, reg, &value)
- `themis_set_reg()` (line 154): SET_REG on VP (domain, vp_id, reg, value)

**Interrupt / Device**:
- `themis_set_intr_policy()` (line 164): SET_INTR_POLICY (domain, vector, visibility)
- `themis_set_def_intr_policy()` (line 172): SET_DEF_INTR_POLICY domain default
- `themis_assign_device()` (line 180): ASSIGN_DEVICE (domain, pci_bdf)

**DomainComm Registration**:
- `themis_register_comm()` (line 190): REGISTER_COMM (cap, child_domain, vp_id)
- `themis_add_vp()` (line 200): ADD_VP (child_domain, comm_cap)

**DomainComm Notification**:
- `themis_domcomm_notify()` (line 211): DOMCOMM_NOTIFY (no args)

### Missing Wrappers for IRQFD/IOEVENTFD

**Not implemented**:
- `themis_set_themic_vector()` — THEMIS_OP_SET_THEMIC_VECTOR (0x17)
- `themis_register_doorbell()` — THEMIS_OP_REGISTER_DOORBELL (0x15)
- `themis_assert_interrupt()` — Custom opcode needed (not defined)

---

## 8. Interrupt Infrastructure

### Current State: **MINIMAL**

**NO interrupt handler registered** for any ThemIC notify vector.

### Interrupt Policy Setup

**THHV_SET_INTR_POLICY** (thhv_part.c:652-666):
```c
case THHV_SET_INTR_POLICY: {
    struct thhv_set_intr_policy ip;
    if (part->sealed)
        return -EBUSY;
    if (copy_from_user(&ip, uarg, sizeof(ip)))
        return -EFAULT;
    if (ip.visibility > THHV_INTR_VISIBILITY_NOT_REPORT)
        return -EINVAL;
    if (ip.vector == THHV_INTR_POLICY_VEC_DEFAULT)
        return themis_set_def_intr_policy(part->domain_handle,
                                          ip.visibility);
    return themis_set_intr_policy(part->domain_handle,
                                  ip.vector, ip.visibility);
}
```

- Allows setting per-vector or domain-default interrupt visibility
- Called **before sealing** the partition
- Visibility options (inc/thhv.h, lines ~772-776):
  - THHV_INTR_VISIBILITY_DELIVER (0): Domain receives interrupt directly
  - THHV_INTR_VISIBILITY_REPORT (1): Forwarded up; domain notified on return
  - THHV_INTR_VISIBILITY_NOT_REPORT (2): Forwarded up; domain not notified

### notify_vector Status

**NOT configured anywhere** in driver:
- No SET_THEMIC_VECTOR (0x17) call
- No interrupt descriptor table (IDT) handler registration
- No IPI/notify mechanism for async VP exits
- Async mode (thhv_vp.c:81) explicitly states TODO to wire IPI path

### dom0 Interrupt Setup

**CPUID detection** (thhv_main.c:21-36):
- Checks for ThemIC presence via THHV_FEAT_THEMIC flag (line 41 in thhv.h)
- No interrupt setup based on feature flags

**Module init** (thhv_main.c:170-192):
1. Calls thhv_detect() → checks CPUID signature
2. Calls thhv_pa_map_init_from_attestation() → loads GPA→HPA map
3. Registers /dev/thhv misc device
4. **No interrupt registration**

---

## 9. thhv.h — IRQFD and IOEVENTFD Definitions

### struct thhv_irqfd (lines ~712-715)

```c
struct thhv_irqfd {
    __s32 fd;          /* eventfd file descriptor */
    __u32 gsi;         /* Global System Interrupt number (0-255) */
    __u32 flags;       /* Control flags (reserved for now) */
    __u32 rsvd;
};
```

**Size**: 16 bytes

### struct thhv_ioeventfd (lines ~716-721)

```c
struct thhv_ioeventfd {
    __s32 fd;          /* eventfd file descriptor */
    __u32 flags;       /* Control flags (datamatch_type, etc.) */
    __u64 addr;        /* Guest physical address (GPA) for doorbell */
    __u32 len;         /* Doorbell region size: 1, 2, or 4 bytes */
    __u32 datamatch;   /* Data pattern to match (if enabled by flags) */
};
```

**Size**: 24 bytes

### IOCTL Macros

**THHV_IRQFD** (lines ~814-815):
```c
#define THHV_IRQFD \
    _IOW(THHV_IOCTL_MAGIC, 0x13, struct thhv_irqfd)
```
- Direction: _IOW (write; only user→kernel)
- Magic: 0xB8
- Command number: 0x13

**THHV_IOEVENTFD** (lines ~817-818):
```c
#define THHV_IOEVENTFD \
    _IOW(THHV_IOCTL_MAGIC, 0x14, struct thhv_ioeventfd)
```
- Direction: _IOW (write; only user→kernel)
- Magic: 0xB8
- Command number: 0x14

---

## 10. Existing EventFD and Workqueue Infrastructure

### EventFD Support: **NONE**

- **No eventfd_ctx imports**: No `#include <linux/eventfd.h>`
- **No eventfd_signal() calls**: No signaling of eventfds anywhere
- **No poll handlers**: No wait_queue or poll support for eventfd integration
- **No eventfd_ctx_get()**: Eventfds are not acquired/held by driver

### Workqueue Support: **NONE**

- **No workqueue declarations**: No `create_workqueue()` or `queue_work()` calls
- **No WORK_STRUCT usage**: No deferred processing of DomainComm messages
- **No kthread usage**: No background processing threads
- **DomainComm drain is manual**: Only called explicitly (domcomm_request_grow) or on demand

### Waitqueue Usage: **PARTIAL (Async Mode Only)**

**struct thhv_vp** has:
```c
wait_queue_head_t exit_wq;      /* Async mode VP exit parking */
atomic_t exit_pending;          /* Exit event flag */
```

**Initialization** (thhv_vp.c:473-474):
```c
init_waitqueue_head(&vp->exit_wq);
atomic_set(&vp->exit_pending, 0);
```

**Wait** (thhv_vp.c:91-92):
```c
ret = wait_event_interruptible(vp->exit_wq,
                               atomic_read(&vp->exit_pending));
```

**Missing**: No code wakes the queue (no `wake_up()` call after DOMCOMM_MSG_VP_EXIT reception).

### Partition-level Lists (for IRQFD/IOEVENTFD)

**Initialized but unused** (thhv_part.c:760-764):
```c
INIT_LIST_HEAD(&part->irqfds);
mutex_init(&part->irqfd_lock);

INIT_LIST_HEAD(&part->ioeventfds.list);
mutex_init(&part->ioeventfds.lock);
```

**Cleanup TODO** (thhv_part.c:92):
```c
/* TODO: free irqfds, ioeventfds */
```

### No Polling or Select Support

- No VFS poll file_operation handlers
- No poll_table registration
- No kselect/kpoll integration

---

## Summary: Implementation Readiness for IRQFD/IOEVENTFD

### IRQFD (P15g) Prerequisites:
1. ✅ struct thhv_irqfd defined
2. ✅ partition->irqfds list + mutex declared
3. ✅ IOCTL stub exists at thhv_part.c:691
4. ❌ Themis VMCALL wrapper for asserting interrupts (custom opcode needed)
5. ❌ No eventfd_ctx management or signaling infrastructure
6. ❌ No interrupt notification vector configured (no SET_THEMIC_VECTOR call)
7. ❌ No IPI handler to trigger eventfd writes

### IOEVENTFD (P15h) Prerequisites:
1. ✅ struct thhv_ioeventfd defined
2. ✅ partition->ioeventfds list + mutex declared
3. ✅ IOCTL stub exists at thhv_part.c:695
4. ❌ Themis wrapper for themis_register_doorbell() (THEMIS_OP_REGISTER_DOORBELL = 0x15)
5. ❌ No eventfd_ctx management infrastructure
6. ❌ No doorbell trigger pathway (DOMCOMM_MSG_DOORBELL → eventfd_signal())
7. ❌ No ThemIC doorbell table setup or lookup

### Critical Infrastructure Gaps:
1. **Async VP exit path incomplete**: exit_pending never set, exit_wq never woken
2. **No interrupt handler**: notify_vector not configured or registered
3. **No DomainComm RX polling**: Only manual dequeue on demand
4. **No eventfd integration**: Standard Linux eventfd patterns not used
5. **No IRQFD-interrupt assertion mapping**: No per-GSI VMCALL infrastructure

---

## File Sizes and Line Counts

```
thhv.h:          ~1050 lines  (39.3 KB)
thhv_main.c:     207 lines
thhv_part.c:     ~813 lines
thhv_vp.c:       575 lines
thhv_hvcall.c:   218 lines
thhv_domcomm.c:  590 lines
thhv_translate.c: (not shown)
```

