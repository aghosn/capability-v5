//! Fixed-size little-endian bootstrap descriptor. Discovery is not attestation.

use super::{
    Error, MAX_BACKING_SIZE, MAX_CHANNELS, MAX_IO_SIZE, MAX_REGIONS, PAGE_SIZE,
    RIGHTS_RW, Service, VERSION as PROTOCOL_VERSION,
};

pub const VERSION: u32 = 2;
pub const FLAG_DEVICE_IO: u32 = 1;
pub const MAGIC: u64 = u64::from_le_bytes(*b"THEMISPV");

pub mod layout {
    pub const HEADER_SIZE: usize = 64;
    pub const REGION_SIZE: usize = 64;
    pub const CHANNEL_SIZE: usize = 96;
    pub const CHANNEL_START: usize = HEADER_SIZE + super::MAX_REGIONS * REGION_SIZE;
    pub const ID_SIZE: usize = 32;

    pub const DESC_MAGIC: usize = 0;
    pub const DESC_VERSION: usize = 8;
    pub const DESC_SIZE: usize = 12;
    pub const DESC_NUM_VPS: usize = 16;
    pub const DESC_NUM_REGIONS: usize = 20;
    pub const DESC_NUM_CHANNELS: usize = 24;
    pub const DESC_FLAGS: usize = 28;
    pub const DESC_GENERATION_LO: usize = 32;
    pub const DESC_GENERATION_HI: usize = 40;
    pub const DESC_RESERVED: usize = 48;

    pub const REGION_GPA: usize = 32;
    pub const REGION_LENGTH: usize = 40;
    pub const REGION_RIGHTS: usize = 48;
    pub const REGION_RESERVED: usize = 56;

    pub const CHANNEL_CONTROL: usize = 32;
    pub const CHANNEL_IO: usize = 36;
    pub const CHANNEL_NUM_VPS: usize = 40;
    pub const CHANNEL_VERSION: usize = 44;
    pub const CHANNEL_SERVICES: usize = 48;
    pub const CHANNEL_RECIPIENT: usize = 56;
    pub const CHANNEL_PORT: usize = 64;
    pub const CHANNEL_RESERVED: usize = 72;
}

use layout::*;

const USED_SIZE: usize = CHANNEL_START + MAX_CHANNELS * CHANNEL_SIZE;
const U32_SIZE: usize = 4;
const U64_SIZE: usize = 8;
pub const KNOWN_SERVICES: u64 =
    Service::Control.bit() | Service::Platform.bit() | Service::Virtio.bit();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Identifier([u8; ID_SIZE]);

impl Identifier {
    pub fn new(value: &str) -> Result<Self, Error> {
        if value.is_empty()
            || value.len() >= ID_SIZE
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(Error::Malformed);
        }
        let mut bytes = [0; ID_SIZE];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self(bytes))
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let end = bytes.iter().position(|&b| b == 0).ok_or(Error::Malformed)?;
        if bytes[end..].iter().any(|&b| b != 0) {
            return Err(Error::Malformed);
        }
        Self::new(core::str::from_utf8(&bytes[..end]).map_err(|_| Error::Malformed)?)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Region {
    pub id: Identifier,
    pub gpa: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Channel {
    pub id: Identifier,
    pub control: u32,
    pub io: u32,
    pub services: u64,
    pub doorbell_recipient: u64,
    pub doorbell_port: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub generation: [u64; 2],
    pub num_vps: u32,
    pub device_io: bool,
    regions: [Region; MAX_REGIONS],
    channels: [Channel; MAX_CHANNELS],
    nr_regions: usize,
    nr_channels: usize,
}

impl Descriptor {
    pub fn new(generation: [u64; 2], num_vps: u32) -> Self {
        Self {
            generation,
            num_vps,
            device_io: false,
            regions: [Region::default(); MAX_REGIONS],
            channels: [Channel::default(); MAX_CHANNELS],
            nr_regions: 0,
            nr_channels: 0,
        }
    }

    pub fn regions(&self) -> &[Region] {
        &self.regions[..self.nr_regions]
    }

    pub fn channels(&self) -> &[Channel] {
        &self.channels[..self.nr_channels]
    }

    pub fn push_region(&mut self, region: Region) -> Result<(), Error> {
        let slot = self.regions.get_mut(self.nr_regions).ok_or(Error::Bounds)?;
        *slot = region;
        self.nr_regions += 1;
        Ok(())
    }

    pub fn push_channel(&mut self, channel: Channel) -> Result<(), Error> {
        let slot = self
            .channels
            .get_mut(self.nr_channels)
            .ok_or(Error::Bounds)?;
        *slot = channel;
        self.nr_channels += 1;
        Ok(())
    }

    pub fn validate(&self, gpa: u64, limit: u64) -> Result<(), Error> {
        self.validate_layout(gpa, limit)?;
        for (i, channel) in self.channels().iter().enumerate() {
            if channel.doorbell_port == 0
                || self.channels()[..i].iter().any(|other|
                    other.doorbell_recipient == channel.doorbell_recipient
                        && other.doorbell_port == channel.doorbell_port)
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }

    pub fn bind_doorbell(&mut self, index: usize, recipient: u64, port: u64) -> Result<(), Error> {
        let channel = self.channels[..self.nr_channels].get_mut(index).ok_or(Error::Bounds)?;
        if port == 0 || channel.doorbell_port != 0 {
            return Err(Error::Malformed);
        }
        channel.doorbell_recipient = recipient;
        channel.doorbell_port = port;
        Ok(())
    }

    pub fn validate_layout(&self, gpa: u64, limit: u64) -> Result<(), Error> {
        if self.generation == [0; 2]
            || self.num_vps == 0
            || self.num_vps > crate::MAX_VPS_PER_DOMAIN
            || self.nr_regions == 0
            || self.nr_channels == 0
        {
            return Err(Error::Malformed);
        }
        range_end(gpa, PAGE_SIZE as u64, limit)?;
        let mut total = 0u64;
        for (i, region) in self.regions().iter().enumerate() {
            if region.id == Identifier::default() {
                return Err(Error::Malformed);
            }
            range_end(region.gpa, region.size, limit)?;
            total = total.checked_add(region.size).ok_or(Error::Bounds)?;
            if total > MAX_BACKING_SIZE || overlaps(region.gpa, region.size, gpa, PAGE_SIZE as u64)
            {
                return Err(Error::Bounds);
            }
            for other in &self.regions()[..i] {
                if region.id == other.id || overlaps(region.gpa, region.size, other.gpa, other.size)
                {
                    return Err(Error::Malformed);
                }
            }
        }
        self.validate_channels()
    }

    fn validate_channels(&self) -> Result<(), Error> {
        if self.device_io
            && !self.channels().iter().any(|channel| {
                channel.services & Service::Control.bit() != 0
                    && channel.services & Service::Platform.bit() != 0
            })
        {
            return Err(Error::Malformed);
        }
        let mut used = [false; MAX_REGIONS];
        for (i, channel) in self.channels().iter().enumerate() {
            if channel.id == Identifier::default()
                || channel.services == 0
                || channel.services & !KNOWN_SERVICES != 0
            {
                return Err(Error::Malformed);
            }
            let control = self
                .regions()
                .get(channel.control as usize)
                .ok_or(Error::Bounds)?;
            let io = self
                .regions()
                .get(channel.io as usize)
                .ok_or(Error::Bounds)?;
            for index in [channel.control as usize, channel.io as usize] {
                if used[index] {
                    return Err(Error::Malformed);
                }
                used[index] = true;
            }
            if control.size != u64::from(self.num_vps) * PAGE_SIZE as u64 || io.size > MAX_IO_SIZE {
                return Err(Error::Bounds);
            }
            if self.channels()[..i].iter().any(|c| c.id == channel.id) {
                return Err(Error::Malformed);
            }
        }
        if used[..self.nr_regions].iter().any(|&v| !v) {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    pub fn encode(&self, bytes: &mut [u8; PAGE_SIZE]) {
        bytes.fill(0);
        put64(bytes, DESC_MAGIC, MAGIC);
        put32(bytes, DESC_VERSION, VERSION);
        put32(bytes, DESC_SIZE, PAGE_SIZE as u32);
        put32(bytes, DESC_NUM_VPS, self.num_vps);
        put32(bytes, DESC_NUM_REGIONS, self.nr_regions as u32);
        put32(bytes, DESC_NUM_CHANNELS, self.nr_channels as u32);
        put32(
            bytes,
            DESC_FLAGS,
            if self.device_io { FLAG_DEVICE_IO } else { 0 },
        );
        put64(bytes, DESC_GENERATION_LO, self.generation[0]);
        put64(bytes, DESC_GENERATION_HI, self.generation[1]);
        for (i, region) in self.regions().iter().enumerate() {
            let off = HEADER_SIZE + i * REGION_SIZE;
            bytes[off..off + ID_SIZE].copy_from_slice(&region.id.0);
            put64(bytes, off + REGION_GPA, region.gpa);
            put64(bytes, off + REGION_LENGTH, region.size);
            put64(bytes, off + REGION_RIGHTS, RIGHTS_RW);
        }
        for (i, channel) in self.channels().iter().enumerate() {
            let off = CHANNEL_START + i * CHANNEL_SIZE;
            bytes[off..off + ID_SIZE].copy_from_slice(&channel.id.0);
            put32(bytes, off + CHANNEL_CONTROL, channel.control);
            put32(bytes, off + CHANNEL_IO, channel.io);
            put32(bytes, off + CHANNEL_NUM_VPS, self.num_vps);
            put32(bytes, off + CHANNEL_VERSION, PROTOCOL_VERSION);
            put64(bytes, off + CHANNEL_SERVICES, channel.services);
            put64(bytes, off + CHANNEL_RECIPIENT, channel.doorbell_recipient);
            put64(bytes, off + CHANNEL_PORT, channel.doorbell_port);
        }
    }

    pub fn decode(bytes: &[u8; PAGE_SIZE]) -> Result<Self, Error> {
        if get64(bytes, DESC_MAGIC) != MAGIC
            || get32(bytes, DESC_VERSION) != VERSION
            || get32(bytes, DESC_SIZE) != PAGE_SIZE as u32
            || get32(bytes, DESC_FLAGS) & !FLAG_DEVICE_IO != 0
            || bytes[DESC_RESERVED..HEADER_SIZE].iter().any(|&v| v != 0)
            || bytes[USED_SIZE..].iter().any(|&v| v != 0)
        {
            return Err(Error::Malformed);
        }
        let nr_regions = get32(bytes, DESC_NUM_REGIONS) as usize;
        let nr_channels = get32(bytes, DESC_NUM_CHANNELS) as usize;
        if nr_regions > MAX_REGIONS || nr_channels > MAX_CHANNELS {
            return Err(Error::Bounds);
        }
        let mut result = Self::new(
            [
                get64(bytes, DESC_GENERATION_LO),
                get64(bytes, DESC_GENERATION_HI),
            ],
            get32(bytes, DESC_NUM_VPS),
        );
        result.device_io = get32(bytes, DESC_FLAGS) & FLAG_DEVICE_IO != 0;
        for i in 0..nr_regions {
            let off = HEADER_SIZE + i * REGION_SIZE;
            if get64(bytes, off + REGION_RIGHTS) != RIGHTS_RW
                || get64(bytes, off + REGION_RESERVED) != 0
            {
                return Err(Error::Malformed);
            }
            result.push_region(Region {
                id: Identifier::decode(&bytes[off..off + ID_SIZE])?,
                gpa: get64(bytes, off + REGION_GPA),
                size: get64(bytes, off + REGION_LENGTH),
            })?;
        }
        for i in 0..nr_channels {
            let off = CHANNEL_START + i * CHANNEL_SIZE;
            if get32(bytes, off + CHANNEL_NUM_VPS) != result.num_vps
                || get32(bytes, off + CHANNEL_VERSION) != PROTOCOL_VERSION
                || get64(bytes, off + CHANNEL_PORT) == 0
                || bytes[off + CHANNEL_RESERVED..off + CHANNEL_SIZE]
                    .iter()
                    .any(|&v| v != 0)
            {
                return Err(Error::Malformed);
            }
            result.push_channel(Channel {
                id: Identifier::decode(&bytes[off..off + ID_SIZE])?,
                control: get32(bytes, off + CHANNEL_CONTROL),
                io: get32(bytes, off + CHANNEL_IO),
                services: get64(bytes, off + CHANNEL_SERVICES),
                doorbell_recipient: get64(bytes, off + CHANNEL_RECIPIENT),
                doorbell_port: get64(bytes, off + CHANNEL_PORT),
            })?;
        }
        let unused_regions = HEADER_SIZE + nr_regions * REGION_SIZE;
        let unused_channels = CHANNEL_START + nr_channels * CHANNEL_SIZE;
        if bytes[unused_regions..CHANNEL_START].iter().any(|&v| v != 0)
            || bytes[unused_channels..USED_SIZE].iter().any(|&v| v != 0)
        {
            return Err(Error::Malformed);
        }
        Ok(result)
    }
}

pub fn range_end(start: u64, size: u64, limit: u64) -> Result<u64, Error> {
    if !start.is_multiple_of(PAGE_SIZE as u64) || size == 0 || !size.is_multiple_of(PAGE_SIZE as u64) {
        return Err(Error::Bounds);
    }
    start
        .checked_add(size)
        .filter(|&end| end <= limit)
        .ok_or(Error::Bounds)
}

fn overlaps(a: u64, alen: u64, b: u64, blen: u64) -> bool {
    a < b.saturating_add(blen) && b < a.saturating_add(alen)
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + U32_SIZE].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + U64_SIZE].copy_from_slice(&value.to_le_bytes());
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + U32_SIZE].try_into().unwrap())
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + U64_SIZE].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pv::AUTO_GPA_START;

    fn descriptor() -> Descriptor {
        let mut d = Descriptor::new([12, 34], 2);
        d.push_region(Region {
            id: Identifier::new("control").unwrap(),
            gpa: AUTO_GPA_START,
            size: 2 * PAGE_SIZE as u64,
        })
        .unwrap();
        d.push_region(Region {
            id: Identifier::new("io").unwrap(),
            gpa: AUTO_GPA_START + MAX_IO_SIZE,
            size: MAX_IO_SIZE,
        })
        .unwrap();
        d.push_channel(Channel {
            id: Identifier::new("parent").unwrap(),
            control: 0,
            io: 1,
            services: 1,
            doorbell_recipient: 0,
            doorbell_port: 42,
        })
        .unwrap();
        d
    }

    const DESCRIPTOR_GPA: u64 = AUTO_GPA_START + 3 * MAX_IO_SIZE;
    const LIMIT: u64 = 1 << 45;

    #[test]
    fn descriptor_round_trip_and_layout_validation() {
        let d = descriptor();
        d.validate(DESCRIPTOR_GPA, LIMIT).unwrap();
        let mut bytes = [0; PAGE_SIZE];
        d.encode(&mut bytes);
        assert_eq!(Descriptor::decode(&bytes).unwrap(), d);
    }

    #[test]
    fn device_transport_flag_requires_platform_and_rejects_unknown_flags() {
        let mut d = descriptor();
        d.device_io = true;
        assert_eq!(d.validate(DESCRIPTOR_GPA, LIMIT), Err(Error::Malformed));
        d.channels[0].services |= Service::Platform.bit();
        d.validate(DESCRIPTOR_GPA, LIMIT).unwrap();
        let mut bytes = [0; PAGE_SIZE];
        d.encode(&mut bytes);
        assert_eq!(Descriptor::decode(&bytes).unwrap(), d);
        put32(&mut bytes, DESC_FLAGS, FLAG_DEVICE_IO | 2);
        assert_eq!(Descriptor::decode(&bytes), Err(Error::Malformed));
    }

    #[test]
    fn malformed_counts_reserved_bytes_and_rights_are_rejected() {
        let mut bytes = [0; PAGE_SIZE];
        descriptor().encode(&mut bytes);
        put32(&mut bytes, DESC_VERSION, 1);
        assert_eq!(Descriptor::decode(&bytes), Err(Error::Malformed));
        descriptor().encode(&mut bytes);
        put32(&mut bytes, DESC_NUM_REGIONS, u32::MAX);
        assert_eq!(Descriptor::decode(&bytes), Err(Error::Bounds));
        descriptor().encode(&mut bytes);
        bytes[PAGE_SIZE - 1] = 1;
        assert_eq!(Descriptor::decode(&bytes), Err(Error::Malformed));
        descriptor().encode(&mut bytes);
        put64(&mut bytes, HEADER_SIZE + REGION_RIGHTS, 7);
        assert_eq!(Descriptor::decode(&bytes), Err(Error::Malformed));
    }

    #[test]
    fn overlapping_or_unowned_memory_is_rejected() {
        let mut d = descriptor();
        d.regions[1].gpa = d.regions[0].gpa;
        assert_eq!(d.validate(DESCRIPTOR_GPA, LIMIT), Err(Error::Malformed));
        let mut d = descriptor();
        d.channels[0].io = 0;
        assert_eq!(d.validate(DESCRIPTOR_GPA, LIMIT), Err(Error::Malformed));
        let mut d = descriptor();
        d.channels[0].doorbell_port = 0;
        assert_eq!(d.validate(DESCRIPTOR_GPA, LIMIT), Err(Error::Malformed));
    }

    #[test]
    fn ranges_cannot_wrap_or_cross_vtom() {
        let mut d = descriptor();
        d.regions[1].gpa = LIMIT;
        assert_eq!(d.validate(DESCRIPTOR_GPA, LIMIT), Err(Error::Bounds));
        assert_eq!(
            range_end(u64::MAX - PAGE_SIZE as u64 + 1, PAGE_SIZE as u64, u64::MAX),
            Err(Error::Bounds)
        );
    }
}
