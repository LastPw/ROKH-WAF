use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackType {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    BadBot,
    RateLimit,
    Clean,
}

impl AttackType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackType::SqlInjection => "SQL_INJECTION",
            AttackType::Xss => "XSS",
            AttackType::PathTraversal => "PATH_TRAVERSAL",
            AttackType::CommandInjection => "COMMAND_INJECTION",
            AttackType::BadBot => "BAD_BOT",
            AttackType::RateLimit => "RATE_LIMIT",
            AttackType::Clean => "CLEAN",
        }
    }
}

pub struct DetectionResult {
    pub is_threat: bool,
    pub attack_type: AttackType,
    pub rule_id: &'static str,
    pub severity: &'static str,
    pub matched_pattern: String,
}

impl DetectionResult {
    pub fn clean() -> Self {
        Self {
            is_threat: false,
            attack_type: AttackType::Clean,
            rule_id: "NONE",
            severity: "INFO",
            matched_pattern: String::new(),
        }
    }
}

struct Rule {
    id: &'static str,
    attack_type: AttackType,
    severity: &'static str,
    pattern: Regex,
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    bot_rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn new() -> Self {
        let mut rules = Vec::new();
        let mut bot_rules = Vec::new();

        // 1. SQL Injection Signatures
        rules.push(Rule {
            id: "SQLI-101",
            attack_type: AttackType::SqlInjection,
            severity: "CRITICAL",
            pattern: Regex::new(r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\binsert\b.*\binto\b|\bdrop\b.*\btable\b|\bupdate\b.*\bset\b|\bdelete\b.*\bfrom\b|\balter\b.*\btable\b|\border\s+by\b.*\b(sleep|benchmark))").unwrap(),
        });
        rules.push(Rule {
            id: "SQLI-102",
            attack_type: AttackType::SqlInjection,
            severity: "HIGH",
            pattern: Regex::new(r#"(\b(or|and)\b\s*[\('"\s]*([0-9a-z_]+|['"]+[^\'"]*['"]+)\s*(=|>|<|!=|like)\s*[\('"\s]*([0-9a-z_]+|['"]+[^\'"]*['"]+)|'\s*(or|and)\s*('|[0-9]+=[0-9]+|[a-z]+=[a-z]+|true|false))"#).unwrap(),
        });
        rules.push(Rule {
            id: "SQLI-103",
            attack_type: AttackType::SqlInjection,
            severity: "HIGH",
            pattern: Regex::new(r"(--|\#|;\s*waitfor\s+delay|\b(sleep|benchmark|pg_sleep)\s*\()").unwrap(),
        });
        rules.push(Rule {
            id: "SQLI-104",
            attack_type: AttackType::SqlInjection,
            severity: "HIGH",
            pattern: Regex::new(r"(\b(exec|execute)\s+(xp_?|sp_?|immediate)|\bdeclare\s+@)").unwrap(),
        });
        rules.push(Rule {
            id: "SQLI-105",
            attack_type: AttackType::SqlInjection,
            severity: "HIGH",
            pattern: Regex::new(r"\b(char|hex|ord|elt|concat|version|user|database|schema|load_file)\s*\(").unwrap(),
        });

        // 2. Cross-Site Scripting (XSS) Signatures
        rules.push(Rule {
            id: "XSS-201",
            attack_type: AttackType::Xss,
            severity: "HIGH",
            pattern: Regex::new(r"(<\s*(script|iframe|object|embed|svg)[^>]*>|javascript\s*:|vbscript\s*:|data\s*:text/html)").unwrap(),
        });
        rules.push(Rule {
            id: "XSS-202",
            attack_type: AttackType::Xss,
            severity: "HIGH",
            pattern: Regex::new(r"(\bon(load|error|click|mouseover|submit|focus|blur|change|input)\s*=)").unwrap(),
        });
        rules.push(Rule {
            id: "XSS-203",
            attack_type: AttackType::Xss,
            severity: "MEDIUM",
            pattern: Regex::new(r"(document\.(cookie|location|write)|window\.location|eval\s*\(|alert\s*\()").unwrap(),
        });

        // 3. Path Traversal & LFI Signatures
        rules.push(Rule {
            id: "PATH-301",
            attack_type: AttackType::PathTraversal,
            severity: "CRITICAL",
            pattern: Regex::new(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)").unwrap(),
        });
        rules.push(Rule {
            id: "PATH-302",
            attack_type: AttackType::PathTraversal,
            severity: "CRITICAL",
            pattern: Regex::new(r"(/etc/passwd|/etc/shadow|/etc/hosts|/proc/|/windows/win\.ini|boot\.ini|\.env|\.git/|\.htaccess|global\.asa|web\.config|php\.ini)").unwrap(),
        });
        rules.push(Rule {
            id: "PATH-303",
            attack_type: AttackType::PathTraversal,
            severity: "CRITICAL",
            pattern: Regex::new(r"(c:[\/\\](windows|winnt|users|documents and settings|inetpub|boot\.ini)|\b(access|error)_log\b|winnt/desktop\.ini|\.ini\b|\.conf\b)").unwrap(),
        });

        // 4. Command Injection & RCE Signatures
        rules.push(Rule {
            id: "RCE-401",
            attack_type: AttackType::CommandInjection,
            severity: "CRITICAL",
            pattern: Regex::new(r"(;|\n|\r|%0a|%0d)\s*(cat|whoami|id|ls|dir|net\s+user|wget|curl|nc|bash|sh|cmd\.exe|powershell|ping)\b").unwrap(),
        });
        rules.push(Rule {
            id: "RCE-402",
            attack_type: AttackType::CommandInjection,
            severity: "CRITICAL",
            pattern: Regex::new(r"(\|\s*(cat|whoami|id|ls|dir|wget|curl|nc|bash|sh|cmd\.exe|powershell|ping)\b)").unwrap(),
        });
        rules.push(Rule {
            id: "RCE-403",
            attack_type: AttackType::CommandInjection,
            severity: "HIGH",
            pattern: Regex::new(r"(`[^`]+`|\$\([^)]+\))").unwrap(),
        });
        rules.push(Rule {
            id: "RCE-404",
            attack_type: AttackType::CommandInjection,
            severity: "CRITICAL",
            pattern: Regex::new(r"(&{1,2}|\|{1,2})\s*(cat|whoami|id|ls|dir|net\s+user|wget|curl|nc|bash|sh|cmd\.exe|powershell|ping)\b").unwrap(),
        });
        rules.push(Rule {
            id: "RCE-405",
            attack_type: AttackType::CommandInjection,
            severity: "HIGH",
            pattern: Regex::new(r"(\b(ping|nslookup|traceroute|phpinfo|passthru|shell_exec)\b|\b(system|exec)\s*\(|\{\$\{|/bin/(cat|sh|bash|id)|/usr/bin/(id|whoami|uname))").unwrap(),
        });
        rules.push(Rule {
            id: "RCE-406",
            attack_type: AttackType::CommandInjection,
            severity: "CRITICAL",
            pattern: Regex::new(r"(<\?php|<\?=|\$_get\[|\$_post\[|\$_request\[|\b(include|require)(_once)?\s*\(|\beval\s*\(|base64_decode\s*\(|echo\s+['\x22]<|>\s*rfi\.php)").unwrap(),
        });

        // 6. Zero-Day, SSRF & Template Injection (SSTI) Signatures
        rules.push(Rule {
            id: "EXP-601",
            attack_type: AttackType::CommandInjection,
            severity: "CRITICAL",
            pattern: Regex::new(r"(\{\{.*\}\}|\$\{[^}]*\}|\b(__proto__|constructor\.prototype|object\.prototype|__globals__|__builtins__|__import__)\b|169\.254\.169\.254|metadata\.google|latest/meta-data)").unwrap(),
        });
        rules.push(Rule {
            id: "AI-602",
            attack_type: AttackType::CommandInjection,
            severity: "HIGH",
            pattern: Regex::new(r"(\bignore\s+previous\s+instructions\b|\bsystem\s+override\b|\bdan\s+mode\s+active\b|\binstruction\s+override\b)").unwrap(),
        });

        // 7. LDAP Injection Signatures
        rules.push(Rule {
            id: "LDAP-701",
            attack_type: AttackType::CommandInjection,
            severity: "HIGH",
            pattern: Regex::new(r"(\*\s*\(|\(\|\s*objectclass=|\*\s*\|\s*\))").unwrap(),
        });

        // 8. Malicious Bot & Vulnerability Scanner Signatures (User-Agent)
        bot_rules.push(Rule {
            id: "BOT-501",
            attack_type: AttackType::BadBot,
            severity: "MEDIUM",
            pattern: Regex::new(r"(sqlmap|nikto|dirbuster|gobuster|nmap|masscan|wpscan|acunetix|havij|nessus)").unwrap(),
        });

        Self { rules, bot_rules }
    }

    /// Evaluates normalized payload against attack signatures
    pub fn inspect(&self, payload: &str) -> DetectionResult {
        for rule in &self.rules {
            if let Some(m) = rule.pattern.find(payload) {
                return DetectionResult {
                    is_threat: true,
                    attack_type: rule.attack_type.clone(),
                    rule_id: rule.id,
                    severity: rule.severity,
                    matched_pattern: m.as_str().to_string(),
                };
            }
        }
        DetectionResult::clean()
    }

    /// Evaluates User-Agent string for known scanners
    pub fn inspect_user_agent(&self, user_agent: &str) -> DetectionResult {
        let ua_lower = user_agent.to_lowercase();
        for rule in &self.bot_rules {
            if let Some(m) = rule.pattern.find(&ua_lower) {
                return DetectionResult {
                    is_threat: true,
                    attack_type: rule.attack_type.clone(),
                    rule_id: rule.id,
                    severity: rule.severity,
                    matched_pattern: m.as_str().to_string(),
                };
            }
        }
        DetectionResult::clean()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chained_rce_detection() {
        let engine = RuleEngine::new();
        let res1 = engine.inspect("something && id");
        assert!(res1.is_threat);
        assert_eq!(res1.rule_id, "RCE-404");

        let res2 = engine.inspect("test && whoami");
        assert!(res2.is_threat);
        assert_eq!(res2.rule_id, "RCE-404");
    }

    #[test]
    fn test_clean_input_passes() {
        let engine = RuleEngine::new();
        let res = engine.inspect("search?category=books&page=1");
        assert!(!res.is_threat);
    }
}
