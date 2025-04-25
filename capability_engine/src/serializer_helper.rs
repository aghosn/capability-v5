pub mod serialize_rights {
    use crate::memory_region::Rights;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(flags: &Rights, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(flags.bits())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Rights, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bits = u8::deserialize(deserializer)?;
        Rights::from_bits(bits).ok_or_else(|| serde::de::Error::custom("invalid rights bitflags"))
    }
}

pub mod serialize_attributes {
    use crate::memory_region::Attributes;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(flags: &Attributes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(flags.bits())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Attributes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bits = u8::deserialize(deserializer)?;
        Attributes::from_bits(bits)
            .ok_or_else(|| serde::de::Error::custom("invalid attributes bitflags"))
    }
}

pub mod serialize_monapi {
    use crate::domain::MonitorAPI;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(flags: &MonitorAPI, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(flags.bits())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<MonitorAPI, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bits = u16::deserialize(deserializer)?;
        MonitorAPI::from_bits(bits)
            .ok_or_else(|| serde::de::Error::custom("invalid monitor api bitflags"))
    }
}

pub mod serialize_visibility {
    use crate::domain::VectorVisibility;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(flags: &VectorVisibility, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(flags.bits())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VectorVisibility, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bits = u8::deserialize(deserializer)?;
        VectorVisibility::from_bits(bits)
            .ok_or_else(|| serde::de::Error::custom("invalid monitor api bitflags"))
    }
}
