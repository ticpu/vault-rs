use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::hash::Hash;
use std::str::FromStr;

/// Represents a certificate serial number that can be formatted in different ways
#[derive(Debug, Clone, Eq)]
pub struct SerialNumber {
    hex: String,
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SerialNumberParseError {
    #[error("Invalid hex character: {0}")]
    InvalidHexCharacter(char),

    #[error("Empty string provided")]
    EmptyString,

    #[error("Invalid length: expected even number of hex characters")]
    InvalidLength,
}

pub type Result<T> = std::result::Result<T, SerialNumberParseError>;

impl SerialNumber {
    /// Create a new SerialNumber from a hex string (with or without colons)
    pub fn new(hex_string: &str) -> Self {
        let hex = hex_string.replace(':', "").to_lowercase();
        Self { hex }
    }

    /// Parse unknown identifiers to confirm if they are a serial number or not
    pub fn parse(identifier: &str) -> Result<Self> {
        if identifier.is_empty() {
            return Err(SerialNumberParseError::EmptyString);
        }

        // Remove colons and convert to lowercase
        let cleaned = identifier.replace(':', "").to_lowercase();

        // Check if length is even (hex pairs)
        if cleaned.len() % 2 != 0 {
            return Err(SerialNumberParseError::InvalidLength);
        }

        // Validate all characters are hex
        for ch in cleaned.chars() {
            if !ch.is_ascii_hexdigit() {
                return Err(SerialNumberParseError::InvalidHexCharacter(ch));
            }
        }

        Ok(Self { hex: cleaned })
    }

    /// Get the raw hex format (no colons)
    pub fn as_hex(&self) -> &str {
        &self.hex
    }

    /// Get the colon-separated hex format (e.g., "3b:fc:2e:b1...")
    pub fn as_colon_hex(&self) -> String {
        self.hex
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex)
    }
}

impl From<&str> for SerialNumber {
    fn from(hex_string: &str) -> Self {
        Self::new(hex_string)
    }
}

impl From<String> for SerialNumber {
    fn from(hex_string: String) -> Self {
        Self::new(&hex_string)
    }
}

impl FromStr for SerialNumber {
    type Err = SerialNumberParseError;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Hash for SerialNumber {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hex.hash(state);
    }
}

impl PartialEq for SerialNumber {
    fn eq(&self, other: &Self) -> bool {
        self.hex == other.hex
    }
}

impl Serialize for SerialNumber {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_colon_hex())
    }
}

impl<'de> Deserialize<'de> for SerialNumber {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SerialNumber::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_number_parse_valid() {
        // Test plain hex string
        let serial = SerialNumber::parse("3bfc2eb1f113a13995271c643668608ebac61322").unwrap();
        assert_eq!(serial.as_hex(), "3bfc2eb1f113a13995271c643668608ebac61322");

        // Test hex string with colons
        let serial =
            SerialNumber::parse("3b:fc:2e:b1:f1:13:a1:39:95:27:1c:64:36:68:60:8e:ba:c6:13:22")
                .unwrap();
        assert_eq!(serial.as_hex(), "3bfc2eb1f113a13995271c643668608ebac61322");

        // Test uppercase hex
        let serial = SerialNumber::parse("ABCD1234").unwrap();
        assert_eq!(serial.as_hex(), "abcd1234");

        // Test mixed case with colons
        let serial = SerialNumber::parse("Ab:Cd:12:34").unwrap();
        assert_eq!(serial.as_hex(), "abcd1234");
    }

    #[test]
    fn test_serial_number_parse_invalid() {
        // Test empty string
        assert!(matches!(
            SerialNumber::parse(""),
            Err(SerialNumberParseError::EmptyString)
        ));

        // Test invalid hex characters
        assert!(matches!(
            SerialNumber::parse("xyz123"),
            Err(SerialNumberParseError::InvalidHexCharacter('x'))
        ));
        assert!(matches!(
            SerialNumber::parse("12g34"),
            Err(SerialNumberParseError::InvalidHexCharacter('g'))
        ));

        // Test odd length (invalid hex pairs)
        assert!(matches!(
            SerialNumber::parse("abc"),
            Err(SerialNumberParseError::InvalidLength)
        ));
        assert!(matches!(
            SerialNumber::parse("12345"),
            Err(SerialNumberParseError::InvalidLength)
        ));

        // Test invalid characters with colons
        assert!(matches!(
            SerialNumber::parse("xy:z1:23"),
            Err(SerialNumberParseError::InvalidHexCharacter('x'))
        ));
    }

    #[test]
    fn test_serial_number_creation() {
        let serial = SerialNumber::new("3bfc2eb1f113a13995271c643668608ebac61322");
        assert_eq!(serial.as_hex(), "3bfc2eb1f113a13995271c643668608ebac61322");
    }

    #[test]
    fn test_serial_number_with_colons() {
        let serial =
            SerialNumber::new("3b:fc:2e:b1:f1:13:a1:39:95:27:1c:64:36:68:60:8e:ba:c6:13:22");
        assert_eq!(serial.as_hex(), "3bfc2eb1f113a13995271c643668608ebac61322");
    }

    #[test]
    fn test_colon_format() {
        let serial = SerialNumber::new("3bfc2eb1f113a13995271c643668608ebac61322");
        assert_eq!(
            serial.as_colon_hex(),
            "3b:fc:2e:b1:f1:13:a1:39:95:27:1c:64:36:68:60:8e:ba:c6:13:22"
        );
    }

    #[test]
    fn test_display() {
        let serial = SerialNumber::new("3bfc2eb1f113a13995271c643668608ebac61322");
        assert_eq!(
            format!("{serial}"),
            "3bfc2eb1f113a13995271c643668608ebac61322"
        );
    }
}
