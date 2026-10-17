use urlencoding::decode;

/// Normalizes and decodes payloads to counter WAF evasion techniques
/// (e.g., double URL encoding, mixed casing, HTML entities, SQL comments).
pub struct Deobfuscator;

impl Deobfuscator {
    #[allow(dead_code)]
    pub fn normalize(input: &str) -> String {
        Self::normalize_with_score(input).0
    }

    pub fn normalize_with_score(input: &str) -> (String, f64) {
        let mut result = input.to_string();
        let mut evasion_score = 0.0f64;

        // 1. Recursive URL decoding (up to 5 iterations to prevent evasion via multi-layer encoding)
        let mut decode_iterations = 0;
        for _ in 0..5 {
            if let Ok(decoded) = decode(&result) {
                if decoded == result {
                    break;
                }
                result = decoded.into_owned();
                decode_iterations += 1;
            } else {
                break;
            }
        }
        if decode_iterations >= 2 {
            evasion_score += 2.0; // Nested URL encoding detected
        }

        // 2. Decode form-urlencoded '+' as space, and remove null bytes
        if result.contains('\0') {
            evasion_score += 3.0; // Null byte poison attempt
            result = result.replace('\0', "");
        }
        result = result.replace('+', " ");

        // 3. Normalize common directory separators
        if result.contains('\\') {
            result = result.replace('\\', "/");
        }

        // 4. HTML entity basic unwrapping
        let pre_html = result.len();
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
        if result.len() != pre_html {
            evasion_score += 1.5;
        }

        // 5. Unicode Full-Width character normalization (evasion mitigation)
        let pre_unicode = result.len();
        result = result
            .replace('＜', "<")
            .replace('＞', ">")
            .replace('＇', "'")
            .replace('＂', "\"")
            .replace('／', "/")
            .replace('＼', "/")
            .replace('；', ";")
            .replace('｜', "|");
        if result.len() != pre_unicode {
            evasion_score += 2.5;
        }

        // 6. Normalize SQL inline comments & unwrap MySQL executable comments
        let mut had_sql_comments = false;
        while let Some(start) = result.find("/*") {
            if let Some(end) = result[start..].find("*/") {
                had_sql_comments = true;
                let actual_end = start + end + 2;
                let comment_slice = &result[start..actual_end];
                if comment_slice.starts_with("/*!") {
                    let inner = &comment_slice[3..comment_slice.len() - 2];
                    let trimmed_inner = inner.trim_start_matches(|c: char| c.is_ascii_digit());
                    let replacement = format!(" {} ", trimmed_inner.trim());
                    result.replace_range(start..actual_end, &replacement);
                } else {
                    result.replace_range(start..actual_end, " ");
                }
            } else {
                break;
            }
        }
        if had_sql_comments {
            evasion_score += 2.5;
        }

        // 7. Whitespace and Control Character Normalization
        result = result
            .replace('\t', " ")
            .replace("\r\n", "\n")
            .replace('\r', "\n");

        while result.contains("  ") {
            result = result.replace("  ", " ");
        }

        (result.to_lowercase(), evasion_score)
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

    #[test]
    fn test_mysql_executable_comment_unwrap() {
        let input = "/*!50000SELECT*/ * /*!50000FROM*/ users";
        let norm = Deobfuscator::normalize(input);
        assert!(norm.contains("select") && norm.contains("from"));
    }

    #[test]
    fn test_preserve_newline_for_rce() {
        let input = "%0aid%0awhoami";
        let norm = Deobfuscator::normalize(input);
        assert!(norm.contains("\nid\nwhoami"));
    }
}
