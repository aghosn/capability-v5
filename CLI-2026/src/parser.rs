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

/// Format Rights as a CLI-parseable string (e.g., "RWX", "RW", "R", "---")
pub fn format_rights(rights: &Rights) -> String {
    let bits = rights.bits();
    if bits == 0 {
        return "---".to_string();
    }
    let mut s = String::new();
    if bits & Rights::READ != 0 { s.push('R'); }
    if bits & Rights::WRITE != 0 { s.push('W'); }
    if bits & Rights::EXECUTE != 0 { s.push('X'); }
    s
}

/// Format Attributes as a CLI-parseable string (e.g., "NONE", "CLEAN", "CLEAN,VITAL")
pub fn format_attributes(attrs: &Attributes) -> String {
    let bits = attrs.bits();
    if bits == 0 {
        return "NONE".to_string();
    }
    let mut parts = Vec::new();
    if bits & Attributes::HASH != 0 { parts.push("HASH"); }
    if bits & Attributes::CLEAN != 0 { parts.push("CLEAN"); }
    if bits & Attributes::VITAL != 0 { parts.push("VITAL"); }
    if bits & Attributes::META != 0 { parts.push("META"); }
    parts.join(",")
}

/// Format MonitorAPI bits as a CLI-parseable string (e.g., "CREATE,SEND,CARVE")
pub fn format_api(api: &MonitorAPI) -> String {
    let bits = api.bits();
    if bits == 0 {
        return "NONE".to_string();
    }
    if bits == MonitorAPI::from_bits(0x1FFF).bits() {
        return "ALL".to_string();
    }
    let flags = [
        (MonitorAPI::CREATE, "CREATE"),
        (MonitorAPI::SET, "SET"),
        (MonitorAPI::GET, "GET"),
        (MonitorAPI::SEND, "SEND"),
        (MonitorAPI::SEAL, "SEAL"),
        (MonitorAPI::ATTEST, "ATTEST"),
        (MonitorAPI::ENUMERATE, "ENUMERATE"),
        (MonitorAPI::SWITCH, "SWITCH"),
        (MonitorAPI::ALIAS, "ALIAS"),
        (MonitorAPI::CARVE, "CARVE"),
        (MonitorAPI::REVOKE, "REVOKE"),
        (MonitorAPI::GETCHAN, "GETCHAN"),
        (MonitorAPI::RECEIVE_AFTER_SEAL, "RECEIVE_AFTER_SEAL"),
    ];
    flags.iter()
        .filter(|(flag, _)| bits & flag != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(",")
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
