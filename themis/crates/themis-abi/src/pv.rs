//! Parent-child PV control protocol. All shared payload words are atomic:
//! the other endpoint may modify any word even while a record is copied.

use core::sync::atomic::{fence, AtomicU64, Ordering};

pub mod descriptor;
pub use descriptor::{Channel, Descriptor, Identifier, Region};

pub const VERSION: u32 = 1;
pub const PAGE_SIZE: usize = 4096;
pub const MAX_REGIONS: usize = 16;
pub const MAX_CHANNELS: usize = 8;
pub const MAX_IO_SIZE: u64 = 24 * 1024 * 1024;
pub const MAX_BACKING_SIZE: u64 = 32 * 1024 * 1024;
pub const AUTO_GPA_START: u64 = 8 * 1024 * 1024 * 1024;
pub const DOORBELL_VALUE: u64 = 1;
pub const RIGHTS_RW: u64 = 3;
pub const OP_NEGOTIATE: u32 = 0;
pub const OP_ECHO: u32 = 1;

pub mod platform {
    pub const IOAPIC_READ: u32 = 0;
    pub const IOAPIC_WRITE: u32 = 1;
    pub const IOAPIC_EOI: u32 = 2;
    pub const IOAPIC_SYNC: u32 = 3;
    /// args: port, width (1/2/4), value (write only); remaining args zero.
    /// A read returns only the width-sized value in completion.values[0].
    pub const PIO_READ: u32 = 4;
    pub const PIO_WRITE: u32 = 5;
    /// args: device address, width (1/2/4/8), value (write only).
    /// Addresses are device-bus operands, never guest-memory copy requests.
    pub const MMIO_READ: u32 = 6;
    pub const MMIO_WRITE: u32 = 7;
    /// args[0]: x2APIC-format ICR, fixed delivery only; remaining args zero.
    /// Physical/logical destinations and all four shorthands are supported.
    pub const IPI_WRITE: u32 = 8;
    // Opcode 9 is retired: it accepted deadlines without timer configuration.
    /// args[0]: absolute TSC deadline (zero disarms); remaining args zero.
    /// A nonzero deadline requires prior TIMER_CONFIG in TSC-deadline mode.
    /// Returns an all-zero success completion.
    pub const TSC_DEADLINE: u32 = 10;
    /// args[0]: timer LVT; remaining args zero. Updates mask/vector even
    /// without rearming a deadline. Returns an all-zero success completion.
    pub const TIMER_CONFIG: u32 = 11;
    pub const IOAPIC_BASE: u64 = 0xfec0_0000;
}

const WORDS: usize = 15;
const RECORD_BYTES: usize = 128;
const RESERVED_WORDS: usize = (PAGE_SIZE - 2 * RECORD_BYTES) / core::mem::size_of::<u64>();
const ARG_START: usize = 5;
const ARG_END: usize = 11;
const HALF_BITS: u32 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Malformed,
    Identity,
    Sequence,
    Busy,
    NoCompletion,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Service {
    Control = 0,
    Platform = 1,
    Virtio = 2,
}

impl Service {
    pub const fn bit(self) -> u64 {
        1 << (self as u32)
    }

    fn decode(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Platform),
            2 => Ok(Self::Virtio),
            _ => Err(Error::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Status {
    Success = 0,
    Unsupported = 1,
    Invalid = 2,
    Failed = 3,
}

impl Status {
    fn decode(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::Unsupported),
            2 => Ok(Self::Invalid),
            3 => Ok(Self::Failed),
            _ => Err(Error::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub generation: [u64; 2],
    pub channel: u32,
    pub vp: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub service: Service,
    pub opcode: u32,
    pub device: u32,
    pub args: [u64; 6],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub status: Status,
    pub values: [u64; 6],
}

impl Completion {
    pub const fn unsupported() -> Self {
        Self {
            status: Status::Unsupported,
            values: [0; 6],
        }
    }
}

#[repr(C)]
struct Record {
    sequence: AtomicU64,
    words: [AtomicU64; WORDS],
}

impl Record {
    fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            words: core::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn publish(&self, sequence: u64, words: [u64; WORDS]) {
        for (dst, src) in self.words.iter().zip(words) {
            dst.store(src, Ordering::Relaxed);
        }
        self.sequence.store(sequence, Ordering::Release);
    }

    fn snapshot(&self, sequence: u64) -> Result<[u64; WORDS], Error> {
        if self.sequence.load(Ordering::Acquire) != sequence {
            return Err(Error::Sequence);
        }
        let words = core::array::from_fn(|i| self.words[i].load(Ordering::Relaxed));
        fence(Ordering::Acquire);
        if self.sequence.load(Ordering::Acquire) != sequence {
            return Err(Error::Sequence);
        }
        Ok(words)
    }
}

#[repr(C, align(4096))]
pub struct ControlPage {
    request: Record,
    completion: Record,
    reserved: [AtomicU64; RESERVED_WORDS],
}

impl Default for ControlPage {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlPage {
    pub fn new() -> Self {
        Self {
            request: Record::new(),
            completion: Record::new(),
            reserved: core::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

const _: () = assert!(core::mem::size_of::<Record>() == RECORD_BYTES);
const _: () = assert!(core::mem::size_of::<ControlPage>() == PAGE_SIZE);

fn pack(low: u32, high: u32) -> u64 {
    u64::from(low) | (u64::from(high) << HALF_BITS)
}

fn encode(identity: Identity, request: Request) -> [u64; WORDS] {
    let mut words = [0; WORDS];
    words[..2].copy_from_slice(&identity.generation);
    words[2] = pack(identity.channel, identity.vp);
    words[3] = pack(request.service as u32, request.opcode);
    words[4] = u64::from(request.device);
    words[ARG_START..ARG_END].copy_from_slice(&request.args);
    words
}

fn validate_identity(words: &[u64; WORDS], identity: Identity) -> Result<(), Error> {
    if words[..2] != identity.generation || words[2] != pack(identity.channel, identity.vp) {
        return Err(Error::Identity);
    }
    if words[ARG_END..].iter().any(|&v| v != 0) {
        return Err(Error::Malformed);
    }
    Ok(())
}

pub struct Client {
    identity: Identity,
    sequence: u64,
    pending: Option<Request>,
}

impl Client {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            sequence: 0,
            pending: None,
        }
    }

    pub fn publish(&mut self, page: &ControlPage, request: Request) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        self.pending = Some(request);
        page.request
            .publish(self.sequence, encode(self.identity, request));
        Ok(())
    }

    pub fn complete(&mut self, page: &ControlPage) -> Result<Completion, Error> {
        let request = self.pending.ok_or(Error::Sequence)?;
        let sequence = page.completion.sequence.load(Ordering::Acquire);
        if sequence < self.sequence {
            return Err(Error::NoCompletion);
        }
        if sequence != self.sequence {
            return Err(Error::Sequence);
        }
        let words = page.completion.snapshot(sequence)?;
        validate_identity(&words, self.identity)?;
        if words[3] != pack(request.service as u32, request.opcode)
            || words[4] as u32 != request.device
        {
            return Err(Error::Identity);
        }
        let status = Status::decode((words[4] >> HALF_BITS) as u32)?;
        let mut values = [0; 6];
        values.copy_from_slice(&words[ARG_START..ARG_END]);
        self.pending = None;
        Ok(Completion { status, values })
    }
}

pub struct Server {
    identity: Identity,
    completed: u64,
}

impl Server {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            completed: 0,
        }
    }

    pub fn service(
        &mut self,
        page: &ControlPage,
        dispatch: impl FnOnce(Request) -> Completion,
    ) -> Result<bool, Error> {
        let sequence = page.request.sequence.load(Ordering::Acquire);
        if sequence == self.completed {
            return Ok(false);
        }
        if sequence != self.completed.checked_add(1).ok_or(Error::Exhausted)? {
            return Err(Error::Sequence);
        }
        let mut words = page.request.snapshot(sequence)?;
        validate_identity(&words, self.identity)?;
        if words[4] >> HALF_BITS != 0 {
            return Err(Error::Malformed);
        }
        let mut args = [0; 6];
        args.copy_from_slice(&words[ARG_START..ARG_END]);
        let request = Request {
            service: Service::decode(words[3] as u32)?,
            opcode: (words[3] >> HALF_BITS) as u32,
            device: words[4] as u32,
            args,
        };
        let completion = dispatch(request);
        words[4] = pack(request.device, completion.status as u32);
        words[ARG_START..ARG_END].copy_from_slice(&completion.values);
        page.completion.publish(sequence, words);
        self.completed = sequence;
        Ok(true)
    }
}

pub fn checked_slice(offset: u64, len: u64, total: u64) -> Result<core::ops::Range<usize>, Error> {
    let end = offset
        .checked_add(len)
        .filter(|&v| v <= total)
        .ok_or(Error::Bounds)?;
    let start = usize::try_from(offset).map_err(|_| Error::Bounds)?;
    let end = usize::try_from(end).map_err(|_| Error::Bounds)?;
    Ok(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: Identity = Identity {
        generation: [42, 43],
        channel: 0,
        vp: 0,
    };
    const REQUEST: Request = Request {
        service: Service::Control,
        opcode: OP_ECHO,
        device: 0,
        args: [1, 2, 3, 4, 5, 6],
    };

    fn echo(request: Request) -> Completion {
        Completion {
            status: Status::Success,
            values: request.args,
        }
    }

    #[test]
    fn successive_round_trips_and_duplicate_notification() {
        let page = ControlPage::new();
        let mut client = Client::new(ID);
        let mut server = Server::new(ID);
        for _ in 0..3 {
            client.publish(&page, REQUEST).unwrap();
            assert_eq!(client.publish(&page, REQUEST), Err(Error::Busy));
            assert!(server.service(&page, echo).unwrap());
            assert!(!server
                .service(&page, |_| panic!("duplicate dispatch"))
                .unwrap());
            assert_eq!(client.complete(&page).unwrap(), echo(REQUEST));
        }
    }

    #[test]
    fn missing_completion_and_reply_identity_fail_closed() {
        let page = ControlPage::new();
        let mut client = Client::new(ID);
        client.publish(&page, REQUEST).unwrap();
        assert_eq!(client.complete(&page), Err(Error::NoCompletion));
        let mut server = Server::new(ID);
        server.service(&page, echo).unwrap();
        page.completion.words[0].store(0, Ordering::Relaxed);
        assert_eq!(client.complete(&page), Err(Error::Identity));
        assert_eq!(client.publish(&page, REQUEST), Err(Error::Busy));
    }

    #[test]
    fn malformed_requests_and_sequences_are_not_dispatched() {
        let page = ControlPage::new();
        let mut client = Client::new(ID);
        let mut server = Server::new(ID);
        client.publish(&page, REQUEST).unwrap();
        page.request.words[ARG_END].store(1, Ordering::Relaxed);
        assert_eq!(
            server.service(&page, |_| panic!("malformed dispatch")),
            Err(Error::Malformed)
        );
        page.request.words[ARG_END].store(0, Ordering::Relaxed);
        page.request.sequence.store(2, Ordering::Release);
        assert_eq!(
            server.service(&page, |_| panic!("skipped sequence")),
            Err(Error::Sequence)
        );
    }

    #[test]
    fn independent_vps_and_session_replay() {
        let page = ControlPage::new();
        let mut client = Client::new(ID);
        client.publish(&page, REQUEST).unwrap();
        for wrong in [
            Identity { vp: 1, ..ID },
            Identity {
                generation: [44, 45],
                ..ID
            },
        ] {
            let mut server = Server::new(wrong);
            assert_eq!(
                server.service(&page, |_| panic!("wrong endpoint")),
                Err(Error::Identity)
            );
        }
        assert!(Server::new(ID).service(&page, echo).unwrap());
        assert_eq!(client.complete(&page).unwrap().values, REQUEST.args);
    }

    #[test]
    fn reply_sequence_and_status_are_validated() {
        let page = ControlPage::new();
        let mut client = Client::new(ID);
        client.publish(&page, REQUEST).unwrap();
        Server::new(ID).service(&page, echo).unwrap();
        page.completion.sequence.store(2, Ordering::Release);
        assert_eq!(client.complete(&page), Err(Error::Sequence));
        page.completion.sequence.store(1, Ordering::Release);
        page.completion.words[4].store(pack(0, u32::MAX), Ordering::Relaxed);
        assert_eq!(client.complete(&page), Err(Error::Malformed));
    }

    #[test]
    fn shared_offsets_cannot_overflow_or_escape_arena() {
        assert_eq!(checked_slice(3, 4, 7), Ok(3..7));
        assert_eq!(checked_slice(3, 5, 7), Err(Error::Bounds));
        assert_eq!(checked_slice(u64::MAX, 1, u64::MAX), Err(Error::Bounds));
    }

    #[test]
    fn dispatch_and_completion_do_not_reread_shared_identity() {
        let page = ControlPage::new();
        let mut client = Client::new(ID);
        client.publish(&page, REQUEST).unwrap();
        Server::new(ID)
            .service(&page, |request| {
                page.request.words[3].store(u64::MAX, Ordering::Relaxed);
                echo(request)
            })
            .unwrap();
        assert_eq!(client.complete(&page).unwrap(), echo(REQUEST));
    }

    #[test]
    fn concurrent_publication_round_trips() {
        extern crate std;
        use std::{sync::Arc, thread};
        const ROUNDS: usize = 1000;
        let page = Arc::new(ControlPage::new());
        let remote = page.clone();
        let server = thread::spawn(move || {
            let mut server = Server::new(ID);
            for _ in 0..ROUNDS {
                while !server.service(&remote, echo).unwrap() {
                    thread::yield_now();
                }
            }
        });
        let mut client = Client::new(ID);
        for _ in 0..ROUNDS {
            client.publish(&page, REQUEST).unwrap();
            loop {
                match client.complete(&page) {
                    Ok(result) => {
                        assert_eq!(result, echo(REQUEST));
                        break;
                    }
                    Err(Error::NoCompletion) => thread::yield_now(),
                    Err(error) => panic!("invalid completion: {error:?}"),
                }
            }
        }
        server.join().unwrap();
    }
}
