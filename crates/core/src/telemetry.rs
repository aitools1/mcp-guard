use serde_json::Value;

pub fn estimate_tokens(value: &Value) -> usize {
    // Rough estimation heuristic: 1 token ~ 4 characters in serialized JSON representation
    let Ok(serialized) = serde_json::to_string(value) else {
        return 0;
    };
    serialized.chars().count().div_ceil(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_estimation() {
        let val = serde_json::json!({
            "name": "read_file",
            "description": "Reads a file from disk given its path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                }
            }
        });
        let tokens = estimate_tokens(&val);
        assert!(tokens > 0);
    }
}
