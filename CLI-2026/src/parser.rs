//! Parsing utilities for CLI commands

use capability_engine::{Attributes, MonitorAPI, Rights};

/// Parse a number from string (supports hex with 0x, binary with 0b, and decimal)
pub fn parse_number(s: &str) -> Result<u64, String> {
    if s.starts_with("0x") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid hex number: {}", e))
    } else if s.starts_with("0b") {
        u64::from_str_radix(&s[2..], 2).map_err(|e| format!("Invalid binary number: {}", e))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("Invalid number: {}", e))
    }
}

/// Parse memory access rights from string (e.g., "RWX", "RW", "R")
pub fn parse_rights(s: &str) -> Result<Rights, String> {
    let mut rights_bits: u8 = 0;
    for c in s.chars() {
        match c {
            'R' | 'r' => rights_bits |= Rights::READ,
            'W' | 'w' => rights_bits |= Rights::WRITE,
            'X' | 'x' => rights_bits |= Rights::EXECUTE,
            '-' => {}
            _ => return Err(format!("Invalid rights character: {}", c)),
        }
    }
    Ok(Rights::from_bits(rights_bits))
}

/// Parse Monitor API permissions from comma-separated string
pub fn parse_api(s: &str) -> Result<MonitorAPI, String> {
    let mut api_bits: u16 = 0;
    for part in s.split(',') {
        let part = part.trim().to_uppercase();
        let flag_bits = match part.as_str() {
            "CREATE" => MonitorAPI::CREATE as u16,
            "SET" => MonitorAPI::SET as u16,
            "GET" => MonitorAPI::GET as u16,
            "SEND" => MonitorAPI::SEND as u16,
            "SEAL" => MonitorAPI::SEAL as u16,
            "ATTEST" => MonitorAPI::ATTEST as u16,
            "ENUMERATE" => MonitorAPI::ENUMERATE as u16,
            "SWITCH" => MonitorAPI::SWITCH as u16,
            "ALIAS" => MonitorAPI::ALIAS as u16,
            "CARVE" => MonitorAPI::CARVE as u16,
            "REVOKE" => MonitorAPI::REVOKE as u16,
            "GETCHAN" => MonitorAPI::GETCHAN as u16,
            "RECEIVE_AFTER_SEAL" => MonitorAPI::RECEIVE_AFTER_SEAL as u16,
            "ALL" => return Ok(MonitorAPI::from_bits(0x1FFF)),
            "NONE" => return Ok(MonitorAPI::from_bits(0)),
            _ => return Err(format!("Invalid API permission: {}", part)),
        };
        api_bits |= flag_bits;
    }
    Ok(MonitorAPI::from_bits(api_bits))
}

/// Parse capability attributes from comma or pipe-separated string
pub fn parse_attributes(s: &str) -> Result<Attributes, String> {
    let mut attrs_bits: u8 = 0;
    // Support both comma and pipe separators
    let separators = [',', '|'];
    for part in s.split(&separators[..]) {
        let part = part.trim().to_uppercase();
        if part.is_empty() {
            continue;
        }
        let flag_bits = match part.as_str() {
            "CLEAN" => Attributes::CLEAN as u8,
            "VITAL" => Attributes::VITAL as u8,
            "HASH" => Attributes::HASH as u8,
            "META" => Attributes::META as u8,
            "NONE" => return Ok(Attributes::from_bits(0)),
            _ => return Err(format!("Invalid attribute: {}", part)),
        };
        attrs_bits |= flag_bits;
    }
    Ok(Attributes::from_bits(attrs_bits))
}
