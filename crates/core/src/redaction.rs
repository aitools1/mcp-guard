use std::sync::LazyLock;
use regex::Regex;
use serde_json::Value;

struct RedactionRule {
    name: &'static str,
    pattern: LazyLock<Regex>,
}

static RULES: LazyLock<Vec<RedactionRule>> = LazyLock::new(|| {
    vec![
        RedactionRule {
            name: "OPENAI",
            pattern: LazyLock::new(|| Regex::new(r"sk-[a-zA-Z0-9\-_]{20,}").unwrap_or_else(|_| Regex::new(r"sk-").unwrap())),
        },
        RedactionRule {
            name: "ANTHROPIC",
            pattern: LazyLock::new(|| Regex::new(r"sk-ant-[a-zA-Z0-9\-]{20,}").unwrap_or_else(|_| Regex::new(r"sk-ant-").unwrap())),
        },
        RedactionRule {
            name: "GITHUB_PAT",
            pattern: LazyLock::new(|| Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap_or_else(|_| Regex::new(r"ghp_").unwrap())),
        },
        RedactionRule {
            name: "AWS_SECRET",
            pattern: LazyLock::new(|| Regex::new(r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"]?\s*[:=]\s*['"]?[a-zA-Z0-9/\+=]{40}['"]?"#).unwrap_or_else(|_| Regex::new(r"AKIA").unwrap())),
        },
        RedactionRule {
            name: "JWT",
            pattern: LazyLock::new(|| Regex::new(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+").unwrap_or_else(|_| Regex::new(r"eyJ").unwrap())),
        },
        RedactionRule {
            name: "BEARER",
            pattern: LazyLock::new(|| Regex::new(r#"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}"#).unwrap_or_else(|_| Regex::new(r"Bearer").unwrap())),
        },
    ]
});

pub fn redact_text(input: &str) -> String {
    let mut result = input.to_string();
    for rule in RULES.iter() {
        let placeholder = format!("[REDACTED:{}]", rule.name);
        result = rule.pattern.replace_all(&result, placeholder.as_str()).to_string();
    }
    result
}

pub fn redact_json(value: &mut Value) {
    match value {
        Value::String(s) => {
            *s = redact_text(s);
        }
        Value::Array(arr) => {
            for item in arr {
                redact_json(item);
            }
        }
        Value::Object(obj) => {
            for (_k, v) in obj {
                redact_json(v);
            }
        }
        _ => {}
    }
}

/// Reports which secret types are present in the input (without modifying it).
/// Used to emit `SecretRedacted` telemetry for the TUI.
pub fn detected_secret_types(input: &str) -> Vec<String> {
    RULES.iter()
        .filter(|r| r.pattern.is_match(input))
        .map(|r| r.name.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_openai() {
        let text = "My key is sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef and some text.";
        let redacted = redact_text(text);
        assert!(redacted.contains("[REDACTED:OPENAI]"));
        assert!(!redacted.contains("sk-proj-"));
    }

    #[test]
    fn test_redact_github_pat() {
        let text = "ghp_123456789012345678901234567890123456";
        let redacted = redact_text(text);
        assert_eq!(redacted, "[REDACTED:GITHUB_PAT]");
    }

    #[test]
    fn test_redact_json() {
        let mut json_val = serde_json::json!({
            "token": "ghp_123456789012345678901234567890123456",
            "nested": {
                "key": "Bearer supersecrettokenvaluetoohardtofindhere12345"
            }
        });
        redact_json(&mut json_val);
        assert_eq!(json_val["token"], "[REDACTED:GITHUB_PAT]");
        assert_eq!(json_val["nested"]["key"], "[REDACTED:BEARER]");
    }

    #[test]
    fn test_detected_secret_types() {
        let types = detected_secret_types("key=sk-abcdefghijklmnopqrstuvwxyz0123456789");
        assert!(types.contains(&"OPENAI".to_string()));
        assert_eq!(detected_secret_types("nothing secret here"), Vec::<String>::new());
    }
}
