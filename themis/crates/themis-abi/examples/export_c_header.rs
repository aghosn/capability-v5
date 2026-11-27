use std::fmt::Write;
use std::mem::{offset_of, size_of};
use std::{env, fs, path::PathBuf};

use themis_abi::domcomm::{
    self, AttestReport, DomCapEntry, DoorbellEntry, Header, MemCapEntry, MsgHeader, PaMapEntry,
    RingMeta, SignedEnvelope,
};
use themis_abi::pv::{self, descriptor, layout};
use themis_abi::{
    cpuid, errors, opcodes, policy_kind, synthetic_exits, vmx_exit_reasons, VpRegister,
};

trait CInteger {
    const SUFFIX: &'static str;
}

macro_rules! c_integer {
    ($suffix:literal: $($ty:ty),*) => {$(
        impl CInteger for $ty {
            const SUFFIX: &'static str = $suffix;
        }
    )*};
}

c_integer!("U": u8, u16, u32);
c_integer!("UL": usize);
c_integer!("ULL": u64);

fn suffix<T: CInteger>(_: &T) -> &'static str {
    T::SUFFIX
}

fn header() -> String {
    let mut output = String::from(
        "/* SPDX-License-Identifier: GPL-2.0 */\n\
         /* Auto-generated from themis-abi Rust definitions. DO NOT EDIT.\n\
         \x20* Regenerate in capability-v5: bash themis/scripts/generate-abi-header.sh [LINUX_DIR]\n\
         \x20* Check copies: bash themis/scripts/generate-abi-header.sh --check [LINUX_DIR]\n\
         \x20* Linux builds use this checked-in copy; Rust is not required.\n\
         \x20*/\n\
         #ifndef _THEMIS_ABI_GENERATED_H\n\
         #define _THEMIS_ABI_GENERATED_H\n\n",
    );
    macro_rules! constants {
        ($($name:ident = $value:expr;)*) => {$({
            let value = $value;
            writeln!(output, "#define {} {:#x}{}",
                     stringify!($name), value as u64, suffix(&value)).unwrap();
        })*};
    }

    constants! {
        THEMIS_OP_CARVE = opcodes::THEMIS_CARVE;
        THEMIS_OP_ALIAS = opcodes::THEMIS_ALIAS;
        THEMIS_OP_SEND = opcodes::THEMIS_SEND;
        THEMIS_OP_ACCEPT = opcodes::THEMIS_ACCEPT;
        THEMIS_OP_REJECT = opcodes::THEMIS_REJECT;
        THEMIS_OP_CREATE_DOMAIN = opcodes::THEMIS_CREATE_DOMAIN;
        THEMIS_OP_SEAL = opcodes::THEMIS_SEAL;
        THEMIS_OP_REVOKE = opcodes::THEMIS_REVOKE;
        THEMIS_OP_SWITCH = opcodes::THEMIS_SWITCH;
        THEMIS_OP_GET_CHAN = opcodes::THEMIS_GET_CHAN;
        THEMIS_OP_ATTEST_SELF = opcodes::THEMIS_ATTEST_SELF;
        THEMIS_OP_ATTEST = opcodes::THEMIS_ATTEST;
        THEMIS_OP_GET_REG = opcodes::THEMIS_GET_REG;
        THEMIS_OP_SET_REG = opcodes::THEMIS_SET_REG;
        THEMIS_OP_ASSIGN_DEVICE = opcodes::THEMIS_ASSIGN_DEVICE;
        THEMIS_OP_RELEASE_DEVICE = opcodes::THEMIS_RELEASE_DEVICE;
        THEMIS_OP_ENUMERATE = opcodes::THEMIS_ENUMERATE;
        THEMIS_OP_ADD_VP = opcodes::THEMIS_ADD_VP;
        THEMIS_OP_REGISTER_COMM = opcodes::THEMIS_REGISTER_COMM;
        THEMIS_OP_DOMCOMM_NOTIFY = opcodes::THEMIS_DOMCOMM_NOTIFY;
        THEMIS_OP_INJECT_INTERRUPT = opcodes::THEMIS_INJECT_INTERRUPT;
        THEMIS_OP_DBG_PRINT = opcodes::THEMIS_DBG_PRINT;
        THEMIS_OP_TOGGLE_DEBUG = opcodes::THEMIS_TOGGLE_DEBUG;
        THEMIS_OP_READ_PCR = opcodes::THEMIS_READ_PCR;
        THEMIS_OP_MAP_SELF = opcodes::THEMIS_MAP_SELF;
        THEMIS_OP_SET_POLICY = opcodes::THEMIS_SET_POLICY;
        THEMIS_OP_CREATE_DOORBELL = opcodes::THEMIS_CREATE_DOORBELL;
        THEMIS_OP_NOTIFY = opcodes::THEMIS_NOTIFY;
        THEMIS_POLICY_CORES = policy_kind::CORES;
        THEMIS_POLICY_API_MONITOR = policy_kind::API_MONITOR;
        THEMIS_POLICY_DEFAULT_INTR_VISIBILITY = policy_kind::DEFAULT_INTR_VISIBILITY;
        THEMIS_POLICY_VECTOR_VISIBILITY = policy_kind::VECTOR_VISIBILITY;
        THEMIS_POLICY_VECTOR_REG_READ_SET = policy_kind::VECTOR_REG_READ_SET;
        THEMIS_POLICY_VECTOR_REG_WRITE_SET = policy_kind::VECTOR_REG_WRITE_SET;
        THEMIS_POLICY_DEFAULT_EXIT_TRAP = policy_kind::DEFAULT_EXIT_TRAP;
        THEMIS_POLICY_EXIT_REASON_TRAP = policy_kind::EXIT_REASON_TRAP;
        THEMIS_POLICY_EXIT_REASON_REG_READ_SET = policy_kind::EXIT_REASON_REG_READ_SET;
        THEMIS_POLICY_EXIT_REASON_REG_WRITE_SET = policy_kind::EXIT_REASON_REG_WRITE_SET;
        THEMIS_POLICY_CPUID_DEFAULT = policy_kind::CPUID_DEFAULT;
        THEMIS_POLICY_CPUID_RANGE = policy_kind::CPUID_RANGE;
        THEMIS_POLICY_CPUID_EMULATE = policy_kind::CPUID_EMULATE;
        THEMIS_POLICY_MSR_DEFAULT = policy_kind::MSR_DEFAULT;
        THEMIS_POLICY_MSR_RANGE = policy_kind::MSR_RANGE;
        THEMIS_POLICY_MSR_EMULATE = policy_kind::MSR_EMULATE;
        THEMIS_POLICY_VECTOR_INJECTABLE = policy_kind::VECTOR_INJECTABLE;
        THEMIS_POLICY_DEFAULT_INTR_REG_READ_SET = policy_kind::DEFAULT_INTR_REG_READ_SET;
        THEMIS_POLICY_DEFAULT_INTR_REG_WRITE_SET = policy_kind::DEFAULT_INTR_REG_WRITE_SET;
        THEMIS_POLICY_DEFAULT_EXIT_REG_READ_SET = policy_kind::DEFAULT_EXIT_REG_READ_SET;
        THEMIS_POLICY_DEFAULT_EXIT_REG_WRITE_SET = policy_kind::DEFAULT_EXIT_REG_WRITE_SET;
        THEMIS_POLICY_DEFAULT_VECTOR_INJECTABLE = policy_kind::DEFAULT_VECTOR_INJECTABLE;
        THEMIS_POLICY_CPUID_EMULATE_RANGE = policy_kind::CPUID_EMULATE_RANGE;
        THEMIS_POLICY_MSR_EMULATE_RANGE = policy_kind::MSR_EMULATE_RANGE;
        THEMIS_POLICY_INHERIT = policy_kind::INHERIT;
        THEMIS_SUCCESS = errors::SUCCESS;
        THEMIS_ERR_INVALID = errors::ERR_INVALID;
        THEMIS_ERR_NOPERM = errors::ERR_NOPERM;
        THEMIS_ERR_NOMEM = errors::ERR_NOMEM;
        THEMIS_ERR_BADSTATE = errors::ERR_BADSTATE;
        THEMIS_ERR_NOTFOUND = errors::ERR_NOTFOUND;
        THEMIS_ERR_BUSY = errors::ERR_BUSY;
        THEMIS_ERR_RETRY = errors::ERR_RETRY;
        THEMIS_ERR_RACE = errors::ERR_RACE;
        THEMIS_ERR_UNIMPL = errors::ERR_UNIMPL;
        THHV_CPUID_LEAF = cpuid::LEAF_BASE;
        THHV_CPUID_FEAT_LEAF = cpuid::LEAF_FEATURES;
        THHV_CPUID_CAP_LEAF = cpuid::LEAF_LIMITS;
        THHV_DOMCOMM_PAGE_LIST = cpuid::DOMCOMM_PAGE_LIST;
        THHV_DOMCOMM_SYNC_GROW = cpuid::DOMCOMM_SYNC_GROW;
        THHV_SIG_EBX = cpuid::SIG_EBX;
        THHV_SIG_ECX = cpuid::SIG_ECX;
        THHV_SIG_EDX = cpuid::SIG_EDX;
        THHV_FEAT_SYNC_SCHED = cpuid::feature_bits::FEATURE_SYNC_SWITCH;
        THHV_FEAT_X2APIC_VIRT = cpuid::feature_bits::FEATURE_X2APIC_VIRT;
        THHV_FEAT_CAPABILITY_DOORBELLS = cpuid::feature_bits::FEATURE_CAPABILITY_DOORBELLS;
        THHV_EXIT_REASON_CPUID = vmx_exit_reasons::CPUID;
        THHV_EXIT_REASON_HLT = vmx_exit_reasons::HLT;
        THHV_EXIT_REASON_IO = vmx_exit_reasons::IO_INSTRUCTION;
        THHV_EXIT_REASON_RDMSR = vmx_exit_reasons::RDMSR;
        THHV_EXIT_REASON_WRMSR = vmx_exit_reasons::WRMSR;
        THHV_EXIT_REASON_EPT_VIOLATION = vmx_exit_reasons::EPT_VIOLATION;
        THHV_EXIT_REASON_YIELD = synthetic_exits::THEMIS_EXIT_YIELD;
        THHV_VP_REG_RAX = VpRegister::Rax as u64;
        THHV_VP_REG_RBX = VpRegister::Rbx as u64;
        THHV_VP_REG_RCX = VpRegister::Rcx as u64;
        THHV_VP_REG_RDX = VpRegister::Rdx as u64;
        THHV_VP_REG_RSI = VpRegister::Rsi as u64;
        THHV_VP_REG_RDI = VpRegister::Rdi as u64;
        THHV_VP_REG_RBP = VpRegister::Rbp as u64;
        THHV_VP_REG_R8 = VpRegister::R8 as u64;
        THHV_VP_REG_R9 = VpRegister::R9 as u64;
        THHV_VP_REG_R10 = VpRegister::R10 as u64;
        THHV_VP_REG_R11 = VpRegister::R11 as u64;
        THHV_VP_REG_R12 = VpRegister::R12 as u64;
        THHV_VP_REG_R13 = VpRegister::R13 as u64;
        THHV_VP_REG_R14 = VpRegister::R14 as u64;
        THHV_VP_REG_R15 = VpRegister::R15 as u64;
        THHV_VP_REG_RSP = VpRegister::Rsp as u64;
        THHV_VP_REG_RIP = VpRegister::Rip as u64;
        THHV_VP_REG_RFLAGS = VpRegister::Rflags as u64;
        THHV_VP_REG_CR0 = VpRegister::Cr0 as u64;
        THHV_VP_REG_CR3 = VpRegister::Cr3 as u64;
        THHV_VP_REG_CR4 = VpRegister::Cr4 as u64;
        THHV_VP_REG_EFER = VpRegister::Efer as u64;
        THHV_VP_REG_DR7 = VpRegister::Dr7 as u64;
        THHV_VP_REG_CS_SEL = VpRegister::CsSelector as u64;
        THHV_VP_REG_DS_SEL = VpRegister::DsSelector as u64;
        THHV_VP_REG_ES_SEL = VpRegister::EsSelector as u64;
        THHV_VP_REG_FS_SEL = VpRegister::FsSelector as u64;
        THHV_VP_REG_GS_SEL = VpRegister::GsSelector as u64;
        THHV_VP_REG_SS_SEL = VpRegister::SsSelector as u64;
        THHV_VP_REG_TR_SEL = VpRegister::TrSelector as u64;
        THHV_VP_REG_LDTR_SEL = VpRegister::LdtrSelector as u64;
        THHV_VP_REG_CS_BASE = VpRegister::CsBase as u64;
        THHV_VP_REG_DS_BASE = VpRegister::DsBase as u64;
        THHV_VP_REG_ES_BASE = VpRegister::EsBase as u64;
        THHV_VP_REG_FS_BASE = VpRegister::FsBase as u64;
        THHV_VP_REG_GS_BASE = VpRegister::GsBase as u64;
        THHV_VP_REG_SS_BASE = VpRegister::SsBase as u64;
        THHV_VP_REG_TR_BASE = VpRegister::TrBase as u64;
        THHV_VP_REG_LDTR_BASE = VpRegister::LdtrBase as u64;
        THHV_VP_REG_CS_LIM = VpRegister::CsLimit as u64;
        THHV_VP_REG_DS_LIM = VpRegister::DsLimit as u64;
        THHV_VP_REG_ES_LIM = VpRegister::EsLimit as u64;
        THHV_VP_REG_FS_LIM = VpRegister::FsLimit as u64;
        THHV_VP_REG_GS_LIM = VpRegister::GsLimit as u64;
        THHV_VP_REG_SS_LIM = VpRegister::SsLimit as u64;
        THHV_VP_REG_TR_LIM = VpRegister::TrLimit as u64;
        THHV_VP_REG_LDTR_LIM = VpRegister::LdtrLimit as u64;
        THHV_VP_REG_CS_AR = VpRegister::CsAccessRights as u64;
        THHV_VP_REG_DS_AR = VpRegister::DsAccessRights as u64;
        THHV_VP_REG_ES_AR = VpRegister::EsAccessRights as u64;
        THHV_VP_REG_FS_AR = VpRegister::FsAccessRights as u64;
        THHV_VP_REG_GS_AR = VpRegister::GsAccessRights as u64;
        THHV_VP_REG_SS_AR = VpRegister::SsAccessRights as u64;
        THHV_VP_REG_TR_AR = VpRegister::TrAccessRights as u64;
        THHV_VP_REG_LDTR_AR = VpRegister::LdtrAccessRights as u64;
        THHV_VP_REG_GDTR_BASE = VpRegister::GdtrBase as u64;
        THHV_VP_REG_GDTR_LIM = VpRegister::GdtrLimit as u64;
        THHV_VP_REG_IDTR_BASE = VpRegister::IdtrBase as u64;
        THHV_VP_REG_IDTR_LIM = VpRegister::IdtrLimit as u64;
        THHV_VP_REG_SYSENTER_CS = VpRegister::SysenterCs as u64;
        THHV_VP_REG_SYSENTER_ESP = VpRegister::SysenterEsp as u64;
        THHV_VP_REG_SYSENTER_EIP = VpRegister::SysenterEip as u64;
        THHV_VP_REG_FS_BASE_MSR = VpRegister::FsBaseMsr as u64;
        THHV_VP_REG_GS_BASE_MSR = VpRegister::GsBaseMsr as u64;
        THHV_VP_REG_KERNEL_GS_BASE = VpRegister::KernelGsBase as u64;
        THHV_VP_REG_APIC_BASE = VpRegister::ApicBase as u64;
        THHV_VP_REG_TPR = VpRegister::Tpr as u64;
        THHV_VP_REG_PPR = VpRegister::Ppr as u64;
        THHV_VP_REG_ACTIVITY_STATE = VpRegister::ActivityState as u64;
        THHV_VP_REG_INTERRUPTIBILITY_STATE = VpRegister::InterruptibilityState as u64;
        THHV_VP_REG_PAT = VpRegister::Pat as u64;
        VP_COMM_MASK_WORDS = themis_abi::regs::VP_COMM_MASK_WORDS;
        VP_COMM_INTERCEPT_OFFSET = themis_abi::regs::VP_COMM_INTERCEPT_OFFSET;
        THEMIC_MSG_SLOT_SIZE = themis_abi::regs::THEMIC_MSG_SLOT_SIZE;
        THEMIC_MSG_NONE = themis_abi::regs::THEMIC_MSG_NONE;
        THEMIC_MSG_VP_INTERCEPT = themis_abi::regs::THEMIC_MSG_VP_INTERCEPT;
        THEMIC_MSG_DOORBELL = themis_abi::regs::THEMIC_MSG_DOORBELL;
        THEMIC_MSG_IRQ_ACK = themis_abi::regs::THEMIC_MSG_IRQ_ACK;
        THEMIC_MSG_SHUTDOWN = themis_abi::regs::THEMIC_MSG_SHUTDOWN;
        THEMIS_MAX_VPS_PER_DOMAIN = themis_abi::MAX_VPS_PER_DOMAIN;
        PV_LEAF = cpuid::LEAF_PV;
        PV_CPUID_CURRENT_VP = cpuid::PV_SUBLEAF_IDENTITY;
        PV_CPUID_VP_VALID = pv::VERSION;
        PV_MAX_VPS = themis_abi::MAX_VPS_PER_DOMAIN;
        PV_REGIONS = pv::MAX_REGIONS;
        PV_CHANNELS = pv::MAX_CHANNELS;
        PV_MAX_BACKING_SIZE = pv::MAX_BACKING_SIZE;
        PV_MAX_IO_SIZE = pv::MAX_IO_SIZE;
        PV_VERSION = pv::VERSION;
        PV_DESCRIPTOR_VERSION = descriptor::VERSION;
        PV_DESCRIPTOR_MAGIC = descriptor::MAGIC;
        PV_ID_SIZE = descriptor::layout::ID_SIZE;
        PV_REGION_SIZE = descriptor::layout::REGION_SIZE;
        PV_CHANNEL_SIZE = descriptor::layout::CHANNEL_SIZE;
        PV_REGION_OFF = descriptor::layout::HEADER_SIZE;
        PV_CHANNEL_OFF = descriptor::layout::CHANNEL_START;
        PV_RIGHTS_RW = pv::RIGHTS_RW;
        PV_DOORBELL_VALUE = pv::DOORBELL_VALUE;
        PV_IOAPIC_BASE = pv::platform::IOAPIC_BASE;
        PV_FLAG_DEVICE_IO = descriptor::FLAG_DEVICE_IO;
        PV_RECORD_SIZE = layout::RECORD_BYTES;
        PV_RECORD_FIELD_BITS = layout::HALF_BITS;
        PV_STATUS_SUCCESS = pv::Status::Success as u32;
        PV_SERVICE_CONTROL = pv::Service::Control as u32;
        PV_SERVICE_PLATFORM = pv::Service::Platform as u32;
        PV_SERVICE_VIRTIO = pv::Service::Virtio as u32;
        PV_SERVICE_CONTROL_BIT = pv::Service::Control.bit();
        PV_SERVICE_PLATFORM_BIT = pv::Service::Platform.bit();
        PV_KNOWN_SERVICES = descriptor::KNOWN_SERVICES;
        PV_NEGOTIATE = pv::OP_NEGOTIATE;
        PV_IOAPIC_READ = pv::platform::IOAPIC_READ;
        PV_IOAPIC_WRITE = pv::platform::IOAPIC_WRITE;
        PV_IOAPIC_EOI = pv::platform::IOAPIC_EOI;
        PV_IOAPIC_SYNC = pv::platform::IOAPIC_SYNC;
        PV_PIO_READ = pv::platform::PIO_READ;
        PV_PIO_WRITE = pv::platform::PIO_WRITE;
        PV_MMIO_READ = pv::platform::MMIO_READ;
        PV_MMIO_WRITE = pv::platform::MMIO_WRITE;
        PV_IPI_WRITE = pv::platform::IPI_WRITE;
        PV_TSC_DEADLINE = pv::platform::TSC_DEADLINE;
        PV_TIMER_CONFIG = pv::platform::TIMER_CONFIG;
        PV_DESC_MAGIC = descriptor::layout::DESC_MAGIC;
        PV_DESC_VERSION = descriptor::layout::DESC_VERSION;
        PV_DESC_SIZE = descriptor::layout::DESC_SIZE;
        PV_DESC_NUM_VPS = descriptor::layout::DESC_NUM_VPS;
        PV_DESC_NUM_REGIONS = descriptor::layout::DESC_NUM_REGIONS;
        PV_DESC_NUM_CHANNELS = descriptor::layout::DESC_NUM_CHANNELS;
        PV_DESC_FLAGS = descriptor::layout::DESC_FLAGS;
        PV_DESC_GENERATION_LO = descriptor::layout::DESC_GENERATION_LO;
        PV_DESC_GENERATION_HI = descriptor::layout::DESC_GENERATION_HI;
        PV_DESC_RESERVED = descriptor::layout::DESC_RESERVED;
        PV_REGION_GPA = descriptor::layout::REGION_GPA;
        PV_REGION_LENGTH = descriptor::layout::REGION_LENGTH;
        PV_REGION_RIGHTS = descriptor::layout::REGION_RIGHTS;
        PV_REGION_RESERVED = descriptor::layout::REGION_RESERVED;
        PV_CHANNEL_CONTROL = descriptor::layout::CHANNEL_CONTROL;
        PV_CHANNEL_IO = descriptor::layout::CHANNEL_IO;
        PV_CHANNEL_NUM_VPS = descriptor::layout::CHANNEL_NUM_VPS;
        PV_CHANNEL_VERSION = descriptor::layout::CHANNEL_VERSION;
        PV_CHANNEL_SERVICES = descriptor::layout::CHANNEL_SERVICES;
        PV_CHANNEL_RECIPIENT = descriptor::layout::CHANNEL_RECIPIENT;
        PV_CHANNEL_PORT = descriptor::layout::CHANNEL_PORT;
        PV_CHANNEL_RESERVED = descriptor::layout::CHANNEL_RESERVED;
        PV_WORD_GENERATION_LO = layout::GENERATION_LO;
        PV_WORD_GENERATION_HI = layout::GENERATION_HI;
        PV_WORD_IDENTITY = layout::IDENTITY;
        PV_WORD_OPERATION = layout::OPERATION;
        PV_WORD_DEVICE_STATUS = layout::DEVICE_STATUS;
        PV_WORD_ARG0 = layout::ARG_START;
        PV_WORD_ARG1 = layout::ARG_START + 1;
        PV_WORD_ARG2 = layout::ARG_START + 2;
        PV_WORD_VALUE0 = layout::ARG_START;
        PV_WORD_VALUE1 = layout::ARG_START + 1;
        PV_WORD_RESERVED = layout::ARG_END;
        PV_RECORD_WORDS = layout::WORDS;
        DOMCOMM_LEAF = domcomm::CPUID_DOMCOMM_LEAF;
        DOMCOMM_MAGIC = domcomm::DOMCOMM_MAGIC;
        DOMCOMM_VERSION_MAJOR = domcomm::DOMCOMM_VERSION_MAJOR;
        DOMCOMM_VERSION_MINOR = domcomm::DOMCOMM_VERSION_MINOR;
        DOMCOMM_MSG_NONE = domcomm::msg_types::NONE;
        DOMCOMM_MSG_ATTEST = domcomm::msg_types::ATTEST;
        DOMCOMM_MSG_VP_EXIT = domcomm::msg_types::VP_EXIT;
        DOMCOMM_MSG_IRQ_NOTIFY = domcomm::msg_types::IRQ_NOTIFY;
        DOMCOMM_MSG_DOMAIN_EVENT = domcomm::msg_types::DOMAIN_EVENT;
        DOMCOMM_MSG_ERROR = domcomm::msg_types::ERROR;
        DOMCOMM_MSG_GROW_ACK = domcomm::msg_types::GROW_ACK;
        DOMCOMM_MSG_DOORBELL_EVENT = domcomm::msg_types::DOORBELL_EVENT;
        DOMCOMM_MSG_ATTEST_REQ = domcomm::msg_types::ATTEST_REQ;
        DOMCOMM_MSG_ACK = domcomm::msg_types::ACK;
        DOMCOMM_MSG_BULK_REG_SET = domcomm::msg_types::BULK_REG_SET;
        DOMCOMM_MSG_GROW_RX = domcomm::msg_types::GROW_RX;
        DOMCOMM_MSG_GROW_TX = domcomm::msg_types::GROW_TX;
        DOMCOMM_MSG_ENUM_CAP = domcomm::msg_types::ENUM_CAP;
        DOMCOMM_FLAG_RX_READY = domcomm::DOMCOMM_FLAG_RX_READY;
        DOMCOMM_FLAG_TX_READY = domcomm::DOMCOMM_FLAG_TX_READY;
        DOMCOMM_ERR_RING_FULL = domcomm::DOMCOMM_ERR_RING_FULL;
        DOMCOMM_ERR_BAD_REQUEST = domcomm::DOMCOMM_ERR_BAD_REQUEST;
        DOMCOMM_MSG_HDR_SIZE = size_of::<MsgHeader>();
        DOMCOMM_MAX_PAYLOAD = domcomm::MAX_PAYLOAD;
        DOMCOMM_VERSION = offset_of!(Header, version_major);
        DOMCOMM_TOTAL_PAGES = offset_of!(Header, total_pages);
        DOMCOMM_RX_HEAD = offset_of!(Header, rx) + offset_of!(RingMeta, head);
        DOMCOMM_RX_TAIL = offset_of!(Header, rx) + offset_of!(RingMeta, tail);
        DOMCOMM_RX_PAGE_OFFSET = offset_of!(Header, rx) + offset_of!(RingMeta, page_offset);
        DOMCOMM_RX_PAGE_COUNT = offset_of!(Header, rx) + offset_of!(RingMeta, page_count);
        DOMCOMM_MSG_TYPE = offset_of!(MsgHeader, message_type);
        DOMCOMM_MSG_SIZE = offset_of!(MsgHeader, total_size);
        DOMCOMM_ATTEST_F_SEALED = domcomm::DOMCOMM_ATTEST_F_SEALED;
        DOMCOMM_ATTEST_F_RETIRED_NOTIFICATIONS = domcomm::DOMCOMM_ATTEST_F_RETIRED_NOTIFICATIONS;
        DOMCOMM_ATTEST_F_DOORBELLS = domcomm::DOMCOMM_ATTEST_F_DOORBELLS;
        ATTEST_HEADER_SIZE = size_of::<AttestReport>();
        ATTEST_SIGNED_ENVELOPE_SIZE = size_of::<SignedEnvelope>();
        ATTEST_KEY_SIZE = domcomm::ATTEST_KEY_SIZE;
        ATTEST_SIG_SIZE = domcomm::ATTEST_SIG_SIZE;
        ATTEST_NONCE_SIZE = domcomm::ATTEST_NONCE_SIZE;
        ATTEST_MEM_CAP_SIZE = size_of::<MemCapEntry>();
        ATTEST_DOM_CAP_SIZE = size_of::<DomCapEntry>();
        ATTEST_PA_MAP_SIZE = size_of::<PaMapEntry>();
        ATTEST_DOORBELL_SIZE = size_of::<DoorbellEntry>();
        ATTEST_DOMAIN_ID = offset_of!(AttestReport, domain_id);
        ATTEST_FLAGS = offset_of!(AttestReport, flags);
        ATTEST_NUM_MEM_CAPS = offset_of!(AttestReport, nr_mem_caps);
        ATTEST_NUM_DOM_CAPS = offset_of!(AttestReport, nr_dom_caps);
        ATTEST_NUM_PA_ENTRIES = offset_of!(AttestReport, nr_pa_entries);
        ATTEST_NUM_DOORBELLS = offset_of!(AttestReport, nr_doorbells);
        ATTEST_DOORBELL_RECIPIENT = offset_of!(DoorbellEntry, recipient);
        ATTEST_DOORBELL_PORT = offset_of!(DoorbellEntry, port);
        ATTEST_DOORBELL_HANDLE = offset_of!(DoorbellEntry, handle);
        ATTEST_DOORBELL_VP = offset_of!(DoorbellEntry, vp);
        ATTEST_DOORBELL_KIND = offset_of!(DoorbellEntry, kind);
        ATTEST_DOORBELL_RESERVED = offset_of!(DoorbellEntry, reserved);
        THEMIS_DOORBELL_SYNC = domcomm::DOORBELL_KIND_SYNC;
        THEMIS_DOORBELL_ASYNC = domcomm::DOORBELL_KIND_ASYNC;
    }
    output.push_str("\n#endif /* _THEMIS_ABI_GENERATED_H */\n");
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut check = false;
    let mut paths = Vec::new();
    for arg in env::args().skip(1) {
        if arg == "--check" {
            check = true;
        } else if arg.starts_with('-') {
            return Err(format!("unknown option: {arg}").into());
        } else {
            paths.push(PathBuf::from(arg));
        }
    }
    if paths.is_empty() {
        return Err("usage: export_c_header [--check] HEADER...".into());
    }
    let header = header();
    for path in paths {
        if check {
            if fs::read_to_string(&path)? != header {
                return Err(format!("stale generated ABI header: {}", path.display()).into());
            }
        } else {
            fs::write(&path, &header)?;
        }
    }
    Ok(())
}
