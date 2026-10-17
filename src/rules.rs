use regex::{Regex, RegexSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackType {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    BadBot,
    RateLimit,
    PromptInjection,
    ZeroDayAnomaly,
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
            AttackType::PromptInjection => "PROMPT_INJECTION",
            AttackType::ZeroDayAnomaly => "ZERO_DAY_ANOMALY",
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
    pattern_str: &'static str,
    pattern: Regex,
}

impl Rule {
    fn new(id: &'static str, attack_type: AttackType, severity: &'static str, pattern_str: &'static str) -> Self {
        Self {
            id,
            attack_type,
            severity,
            pattern_str,
            pattern: Regex::new(pattern_str).expect("Valid signature regex"),
        }
    }
}

pub struct RuleEngine {
    rule_set: RegexSet,
    rules: Vec<Rule>,
    bot_set: RegexSet,
    bot_rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn new() -> Self {
        let mut rules = Vec::new();
        let mut bot_rules = Vec::new();

        // 1. SQL Injection Signatures
        rules.push(Rule::new(
            "SQLI-101",
            AttackType::SqlInjection,
            "CRITICAL",
            r"(?is)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\binsert\b.*\binto\b|\bdrop\b.*\btable\b|\bupdate\b.*\bset\b|\bdelete\b.*\bfrom\b|\balter\b.*\btable\b|\border\s+by\b.*\b(sleep|benchmark))",
        ));
        rules.push(Rule::new(
            "SQLI-102",
            AttackType::SqlInjection,
            "HIGH",
            r#"(?is)(\b(or|and)\b\s*[\('"\s]*([0-9a-z_]+|['"]+[^'"]*['"]*)\s*(=|>|<|!=|like|rlike|regexp)\s*[\('"\s]*([0-9a-z_]+|['"]+[^'"]*['"]*)|['"]\s*(or|and)\s*('|[0-9]+=[0-9]+|[a-z]+=[a-z]+|true|false))"#,
        ));
        rules.push(Rule::new(
            "SQLI-103",
            AttackType::SqlInjection,
            "HIGH",
            r"(?is)(--|\#|;\s*waitfor\s+delay|\b(sleep|benchmark|pg_sleep)\s*\()",
        ));
        rules.push(Rule::new(
            "SQLI-104",
            AttackType::SqlInjection,
            "HIGH",
            r"(?is)(\b(exec|execute)\s+(xp_?|sp_?|immediate)|\bdeclare\s+@)",
        ));
        rules.push(Rule::new(
            "SQLI-105",
            AttackType::SqlInjection,
            "HIGH",
            r"(?is)\b(char|hex|unhex|ord|elt|concat|concat_ws|version|user|database|schema|load_file|extractvalue|updatexml|geometrycollection)\s*\(",
        ));
        rules.push(Rule::new(
            "SQLI-106",
            AttackType::SqlInjection,
            "CRITICAL",
            r"(?is)(/\*![0-9]*|\bunion\s+all\s+select\b|;\s*(drop|truncate|alter|create|insert|update|delete)\s+)",
        ));

        // 2. Cross-Site Scripting (XSS) Signatures
        rules.push(Rule::new(
            "XSS-201",
            AttackType::Xss,
            "HIGH",
            r"(?is)(<\s*(script|iframe|object|embed|svg|img|details|audio|video|body|input)[^>]*>|javascript\s*:|vbscript\s*:|data\s*:text/html)",
        ));
        rules.push(Rule::new(
            "XSS-202",
            AttackType::Xss,
            "HIGH",
            r"(?is)(\bon[a-z]{3,18}\s*=)",
        ));
        rules.push(Rule::new(
            "XSS-203",
            AttackType::Xss,
            "MEDIUM",
            r"(?is)(document\.(cookie|location|write|domain)|window\.(location|navigate)|eval\s*\(|alert\s*\(|confirm\s*\(|prompt\s*\()",
        ));

        // 3. Path Traversal & LFI Signatures
        rules.push(Rule::new(
            "PATH-301",
            AttackType::PathTraversal,
            "CRITICAL",
            r"(?is)(\.\.[;/]|\.\.\\|%2e%2e[/%2f]|%2e%2e;|\.\.%2f)",
        ));
        rules.push(Rule::new(
            "PATH-302",
            AttackType::PathTraversal,
            "CRITICAL",
            r"(?is)(/etc/(passwd|shadow|hosts|group|issue)|/proc/self/|/windows/win\.ini|boot\.ini|\.env|\.git/|\.htaccess|global\.asa|web\.config|php\.ini|id_rsa|id_ed25519)",
        ));
        rules.push(Rule::new(
            "PATH-303",
            AttackType::PathTraversal,
            "CRITICAL",
            r"(?is)(c:[\/\\](windows|winnt|users|documents and settings|inetpub|boot\.ini)|\b(access|error)_log\b|winnt/desktop\.ini|\.ini\b|\.conf\b)",
        ));

        // 4. Command Injection & RCE Signatures
        rules.push(Rule::new(
            "RCE-407",
            AttackType::CommandInjection,
            "CRITICAL",
            r"(?is)(\(\s*\)\s*\{\s*:;\s*\};)",
        ));
        rules.push(Rule::new(
            "RCE-401",
            AttackType::CommandInjection,
            "CRITICAL",
            r"(?is)([;&|`\n\r]|%0a|%0d)\s*(cat|whoami|id|ls|dir|net\s+user|wget|curl|nc|bash|sh|cmd\.exe|powershell|ping)\b",
        ));
        rules.push(Rule::new(
            "RCE-402",
            AttackType::CommandInjection,
            "CRITICAL",
            r"(?is)(\|\s*(cat|whoami|id|ls|dir|wget|curl|nc|bash|sh|cmd\.exe|powershell|ping)\b)",
        ));
        rules.push(Rule::new(
            "RCE-403",
            AttackType::CommandInjection,
            "HIGH",
            r"(?is)(`[^`]+`|\$\([^)]+\))",
        ));
        rules.push(Rule::new(
            "RCE-404",
            AttackType::CommandInjection,
            "CRITICAL",
            r"(?is)(&{1,2}|\|{1,2})\s*(cat|whoami|id|ls|dir|net\s+user|wget|curl|nc|bash|sh|cmd\.exe|powershell|ping)\b",
        ));
        rules.push(Rule::new(
            "RCE-405",
            AttackType::CommandInjection,
            "HIGH",
            r"(?is)(\b(ping|nslookup|traceroute|phpinfo|passthru|shell_exec)\b|\b(system|exec|popen|proc_open)\s*\(|\{\$\{|/bin/(cat|sh|bash|id)|/usr/bin/(id|whoami|uname))",
        ));
        rules.push(Rule::new(
            "RCE-406",
            AttackType::CommandInjection,
            "CRITICAL",
            r"(?is)(<\?php|<\?=|\$_get\[|\$_post\[|\$_request\[|\b(include|require)(_once)?\s*\(|\beval\s*\(|base64_decode\s*\(|echo\s+['\x22]<|>\s*rfi\.php)",
        ));
        rules.push(Rule::new(
            "RCE-408",
            AttackType::CommandInjection,
            "CRITICAL",
            r"(?is)(^|[\s;&|`\n\r])(cat\s+[/.]|whoami\b|id\s*([;&|`\n\r]|$)|/bin/(cat|sh|bash|id)|/usr/bin/(id|whoami|uname)|net\s+user\b|dir\s+[a-zA-Z]:[/\\]|curl\s+https?://|wget\s+https?://)",
        ));
        rules.push(Rule::new(
            "RCE-409",
            AttackType::CommandInjection,
            "HIGH",
            r"(?is)(\$(IFS|\{IFS\}|\{cat,|\{whoami,)|/dev/(tcp|udp)/\d+|\|\s*(base64\s+-d|sh|bash)\b|\{\$\{[^}]+\}\})",
        ));

        // 6. Zero-Day, SSRF & Template Injection (SSTI) Signatures
        rules.push(Rule::new(
            "EXP-601",
            AttackType::CommandInjection,
            "CRITICAL",
            r"(?is)(\{\{.*\}\}|\$\{[^}]*\}|\b(__proto__|constructor\.prototype|object\.prototype|__globals__|__builtins__|__import__)\b|169\.254\.169\.254|metadata\.google|latest/meta-data)",
        ));
        rules.push(Rule::new(
            "AI-602",
            AttackType::CommandInjection,
            "HIGH",
            r"(?is)(\bignore\s+previous\s+instructions\b|\bsystem\s+override\b|\bdan\s+mode\s+active\b|\binstruction\s+override\b)",
        ));

        // 7. LDAP Injection Signatures
        rules.push(Rule::new(
            "LDAP-701",
            AttackType::CommandInjection,
            "HIGH",
            r"(?is)(\*\s*\(|\(\|\s*objectclass=|\*\s*\|\s*\))",
        ));

        // 8. Malicious Bot & Vulnerability Scanner Signatures (User-Agent)
        bot_rules.push(Rule::new(
            "BOT-501",
            AttackType::BadBot,
            "MEDIUM",
            r"(?is)(sqlmap|nikto|dirbuster|gobuster|nmap|masscan|wpscan|acunetix|havij|nessus)",
        ));

        // Compile multi-pattern automata (Aho-Corasick + Lazy DFA) for single-pass O(N) evaluation
        let rule_patterns: Vec<&str> = rules.iter().map(|r| r.pattern_str).collect();
        let rule_set = RegexSet::new(&rule_patterns).expect("Failed to compile OWASP RegexSet");

        let bot_patterns: Vec<&str> = bot_rules.iter().map(|r| r.pattern_str).collect();
        let bot_set = RegexSet::new(&bot_patterns).expect("Failed to compile Bot RegexSet");

        Self {
            rule_set,
            rules,
            bot_set,
            bot_rules,
        }
    }

    /// Evaluates normalized payload against attack signatures in a single O(N) pass
    pub fn inspect(&self, payload: &str) -> DetectionResult {
        let matches = self.rule_set.matches(payload);
        if !matches.matched_any() {
            return DetectionResult::clean();
        }

        // Return the first matching signature in precedence order
        for idx in matches.into_iter() {
            let rule = &self.rules[idx];
            let matched_pattern = rule
                .pattern
                .find(payload)
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| rule.id.to_string());

            return DetectionResult {
                is_threat: true,
                attack_type: rule.attack_type.clone(),
                rule_id: rule.id,
                severity: rule.severity,
                matched_pattern,
            };
        }

        DetectionResult::clean()
    }

    /// Evaluates User-Agent string for known scanners in a single O(N) pass
    pub fn inspect_user_agent(&self, user_agent: &str) -> DetectionResult {
        let ua_lower = user_agent.to_lowercase();
        let matches = self.bot_set.matches(&ua_lower);
        if !matches.matched_any() {
            return DetectionResult::clean();
        }

        for idx in matches.into_iter() {
            let rule = &self.bot_rules[idx];
            let matched_pattern = rule
                .pattern
                .find(&ua_lower)
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| rule.id.to_string());

            return DetectionResult {
                is_threat: true,
                attack_type: rule.attack_type.clone(),
                rule_id: rule.id,
                severity: rule.severity,
                matched_pattern,
            };
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
        assert_eq!(res1.attack_type, AttackType::CommandInjection);

        let res2 = engine.inspect("test && whoami");
        assert!(res2.is_threat);
        assert_eq!(res2.attack_type, AttackType::CommandInjection);
    }

    #[test]
    fn test_clean_input_passes() {
        let engine = RuleEngine::new();
        let res = engine.inspect("search?category=books&page=1");
        assert!(!res.is_threat);
    }

    #[test]
    fn test_shellshock_cve_2014_6271() {
        let engine = RuleEngine::new();
        let res = engine.inspect("() { :;}; /bin/bash -c 'sleep 5'");
        assert!(res.is_threat);
        assert_eq!(res.rule_id, "RCE-407");
    }

    #[test]
    fn test_direct_command_execution() {
        let engine = RuleEngine::new();
        let res = engine.inspect("cat /var/log/syslog");
        assert!(res.is_threat);
        assert_eq!(res.rule_id, "RCE-408");

        let res2 = engine.inspect("whoami");
        assert!(res2.is_threat);
        assert_eq!(res2.rule_id, "RCE-408");
    }

    #[test]
    fn test_html5_event_handler_xss() {
        let engine = RuleEngine::new();
        let res = engine.inspect("<details ontoggle=alert(1)>");
        assert!(res.is_threat);
    }

    #[test]
    fn test_tomcat_path_traversal() {
        let engine = RuleEngine::new();
        let res = engine.inspect("..;/..;/etc/passwd");
        assert!(res.is_threat);
        assert_eq!(res.rule_id, "PATH-301");
    }
}
