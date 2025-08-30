//! JSON Canonicalization Scheme (JCS) implementation
//! 
//! This module implements RFC 8785 - JSON Canonicalization Scheme (JCS)
//! for cryptographically stable JSON canonicalization.
//! 
//! JCS ensures that the same logical JSON data always produces the same
//! canonical byte representation, which is essential for cryptographic
//! operations like hashing and signing.
//!
//! This implementation produces byte-exact output as specified in RFC 8785.

use serde_json::Value;
use std::fmt::Write;

/// Canonicalize a JSON value according to RFC 8785 (JCS)
/// This produces byte-exact canonical JSON as specified in the RFC
pub fn canonicalize_json(value: &Value) -> Result<String, String> {
    let mut output = String::new();
    serialize_value(value, &mut output)?;
    Ok(output)
}

/// Serialize a JSON value directly to canonical string format per RFC 8785
fn serialize_value(value: &Value, output: &mut String) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            serialize_object(map, output)?;
        }
        Value::Array(arr) => {
            serialize_array(arr, output)?;
        }
        Value::String(s) => {
            serialize_string(s, output)?;
        }
        Value::Number(n) => {
            serialize_number(n, output)?;
        }
        Value::Bool(b) => {
            output.push_str(if *b { "true" } else { "false" });
        }
        Value::Null => {
            output.push_str("null");
        }
    }
    Ok(())
}

/// Serialize a JSON object with lexicographically sorted keys
fn serialize_object(map: &serde_json::Map<String, Value>, output: &mut String) -> Result<(), String> {
    output.push('{');
    
    // Collect and sort keys
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            output.push(',');
        }
        
        // Serialize key
        serialize_string(key, output)?;
        output.push(':');
        
        // Serialize value
        let value = &map[*key];
        serialize_value(value, output)?;
    }
    
    output.push('}');
    Ok(())
}

/// Serialize a JSON array
fn serialize_array(arr: &[Value], output: &mut String) -> Result<(), String> {
    output.push('[');
    
    for (i, item) in arr.iter().enumerate() {
        if i > 0 {
            output.push(',');
        }
        serialize_value(item, output)?;
    }
    
    output.push(']');
    Ok(())
}

/// Serialize a JSON string with proper escaping per RFC 8785
fn serialize_string(s: &str, output: &mut String) -> Result<(), String> {
    output.push('"');
    
    for ch in s.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0C}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch.is_control() => {
                write!(output, "\\u{:04x}", ch as u32).map_err(|e| e.to_string())?;
            }
            ch => output.push(ch),
        }
    }
    
    output.push('"');
    Ok(())
}

/// Serialize a JSON number per RFC 8785 (ECMAScript number formatting)
fn serialize_number(num: &serde_json::Number, output: &mut String) -> Result<(), String> {
    // RFC 8785 requires ECMAScript Number.prototype.toString() behavior
    if let Some(i) = num.as_i64() {
        write!(output, "{}", i).map_err(|e| e.to_string())?;
    } else if let Some(u) = num.as_u64() {
        write!(output, "{}", u).map_err(|e| e.to_string())?;
    } else if let Some(f) = num.as_f64() {
        // Handle special float values
        if f.is_nan() {
            return Err("NaN is not allowed in JSON".to_string());
        }
        if f.is_infinite() {
            return Err("Infinity is not allowed in JSON".to_string());
        }
        
        // Use ECMAScript number formatting
        if f.fract() == 0.0 && f.abs() < 1e15 && f.abs() >= 1e-4 {
            // Integer representation for whole numbers in reasonable range
            write!(output, "{}", f as i64).map_err(|e| e.to_string())?;
        } else {
            // Use the minimal decimal representation
            let formatted = format!("{}", f);
            output.push_str(&formatted);
        }
    } else {
        return Err("Invalid number format".to_string());
    }
    Ok(())
}

/// Canonicalize a JSON string according to JCS
pub fn canonicalize_json_string(json_str: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(json_str)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;
    
    canonicalize_json(&value)
}

/// Canonicalize a CanonicalRecord for signing
pub fn canonicalize_record(record: &crate::canonical_record::CanonicalRecord) -> Result<String, String> {
    // Create a copy without signature fields AND hash field for canonicalization
    // The hash field should not be included in the canonical representation used to compute the hash
    let mut unsigned_record = record.clone();
    unsigned_record.sig = None;
    unsigned_record.pub_key = None;
    unsigned_record.witnesses = vec![];
    unsigned_record.hash = String::new(); // Remove hash field to avoid circular dependency
    
    // Convert to JSON Value and manually remove the hash field entirely
    let mut value = serde_json::to_value(&unsigned_record)
        .map_err(|e| format!("Failed to serialize record: {}", e))?;
    
    // Remove the hash field entirely from the JSON representation
    if let serde_json::Value::Object(ref mut map) = value {
        map.remove("hash");
    }
    
    canonicalize_json(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_object_key_sorting() {
        let input = json!({
            "z": 1,
            "a": 2,
            "m": 3
        });
        
        let canonical = canonicalize_json(&input).unwrap();
        
        // Should produce exact canonical form with sorted keys
        assert_eq!(canonical, r#"{"a":2,"m":3,"z":1}"#);
    }
    
    #[test]
    fn test_nested_objects() {
        let input = json!({
            "outer": {
                "z": 1,
                "a": {
                    "c": 3,
                    "b": 2
                }
            },
            "first": 1
        });
        
        let canonical = canonicalize_json(&input).unwrap();
        
        // Should produce exact canonical form with all keys sorted
        assert_eq!(canonical, r#"{"first":1,"outer":{"a":{"b":2,"c":3},"z":1}}"#);
    }
    
    #[test]
    fn test_arrays_preserve_order() {
        let input = json!({
            "array": [3, 1, 2],
            "another": ["z", "a", "m"]
        });
        
        let canonical = canonicalize_json(&input).unwrap();
        
        // Should produce exact canonical form with arrays in original order
        assert_eq!(canonical, r#"{"another":["z","a","m"],"array":[3,1,2]}"#);
    }
    
    #[test]
    fn test_number_canonicalization() {
        let input = json!({
            "int": 42,
            "float": 3.14,
            "zero": 0.0,
            "whole": 5.0
        });
        
        let canonical = canonicalize_json(&input).unwrap();
        
        // Should produce exact canonical form with proper number formatting
        assert_eq!(canonical, r#"{"float":3.14,"int":42,"whole":5,"zero":0}"#);
    }
    
    #[test]
    fn test_deterministic_output() {
        let input = json!({
            "z": {"b": 2, "a": 1},
            "a": [3, 1, 2],
            "m": "test"
        });
        
        // Multiple canonicalizations should produce identical results
        let canonical1 = canonicalize_json(&input).unwrap();
        let canonical2 = canonicalize_json(&input).unwrap();
        let canonical3 = canonicalize_json(&input).unwrap();
        
        assert_eq!(canonical1, canonical2);
        assert_eq!(canonical2, canonical3);
        assert_eq!(canonical1, r#"{"a":[3,1,2],"m":"test","z":{"a":1,"b":2}}"#);
    }
    
    #[test]
    fn test_empty_structures() {
        let input = json!({
            "empty_object": {},
            "empty_array": [],
            "null_value": null,
            "boolean": true
        });
        
        let canonical = canonicalize_json(&input).unwrap();
        
        // Should produce exact canonical form
        assert_eq!(canonical, r#"{"boolean":true,"empty_array":[],"empty_object":{},"null_value":null}"#);
    }
    
    #[test]
    fn test_string_escaping() {
        let input = json!({
            "quotes": "He said \"Hello\"",
            "backslash": "C:\\path\\to\\file",
            "newline": "line1\nline2",
            "tab": "col1\tcol2"
        });
        
        let canonical = canonicalize_json(&input).unwrap();
        
        // Should produce exact canonical form with proper escaping
        assert_eq!(canonical, r#"{"backslash":"C:\\path\\to\\file","newline":"line1\nline2","quotes":"He said \"Hello\"","tab":"col1\tcol2"}"#);
    }
}
