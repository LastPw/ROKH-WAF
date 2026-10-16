use urlencoding::decode;

/// Normalizes and decodes payloads to counter WAF evasion techniques
/// (e.g., double URL encoding, mixed casing, HTML entities, SQL comments).
pub struct Deobfuscator;

impl Deobfuscator {
    pub fn normalize(input: &str) -> String {
        let mut result = input.to_string();

        // 1. Recursive URL decoding (up to 5 iterations to prevent evasion via multi-layer encoding)
        for _ in 0..5 {
            if let Ok(decoded) = decode(&result) {
                if decoded == result {
                    break;
                }
                result = decoded.into_owned();
            } else {
                break;
            }
        }

        // 2. Remove null bytes and non-printable control characters
        result = result.replace('\0', "");

        // 3. Normalize common directory separators
        result = result.replace('\\', "/");

        // 4. HTML entity basic unwrapping
        result = result
            .replace("&quot;", "\"")
            .replace("&#34;", "\"")
            .replace("&apos;", "'")
            .replace("&#39;", "'")
            .replace("&#x27;", "'")
            .replace("&lt;", "<")
            .replace("&#60;", "<")
            .replace("&#x3c;", "<")
            .replace("&gt;", ">")
            .replace("&#62;", ">")
            .replace("&#x3e;", ">")
            .replace("&colon;", ":")
            .replace("&lpar;", "(")
            .replace("&rpar;", ")")
            .replace("&tab;", " ")
            .replace("&period;", ".");

        // 5. Unicode Full-Width character normalization (evasion mitigation)
        result = result
            .replace('＜', "<")
            .replace('＞', ">")
            .replace('＇', "'")
            .replace('＂', "\"")
            .replace('／', "/")
            .replace('＼', "/")
            .replace('；', ";")
            .replace('｜', "|");

        // 5. Normalize SQL inline comments (e.g. UN/**/ION SEL/**/ECT -> UN ION SEL ECT)
        while let Some(start) = result.find("/*") {
            if let Some(end) = result[start..].find("*/") {
                let actual_end = start + end + 2;
                result.replace_range(start..actual_end, " ");
            } else {
                break;
            }
        }

        // 6. Whitespace and Control Character Normalization (mitigate tab/newline token splitting)
        result = result.replace('\t', " ").replace('\r', " ").replace('\n', " ");
        while result.contains("  ") {
            result = result.replace("  ", " ");
        }

        // 7. Convert to lowercase for uniform regex matching
        result.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_url_decode() {
        // %252e%252e%252f -> %2e%2e%2f -> ../
        let input = "%252e%252e%252fetc%252fpasswd";
        let norm = Deobfuscator::normalize(input);
        assert!(norm.contains("../etc/passwd"));
    }

    #[test]
    fn test_sql_comment_evasion() {
        let input = "UN/**/ION/**/SEL/**/ECT";
        let norm = Deobfuscator::normalize(input);
        assert!(norm.contains("un ion sel ect"));
    }

    #[test]
    fn test_html_entity_decode() {
        let input = "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;";
        let norm = Deobfuscator::normalize(input);
        assert!(norm.contains("<script>alert('xss')</script>"));
    }
}
