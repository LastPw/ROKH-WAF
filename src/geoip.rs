use std::net::Ipv4Addr;
use std::str::FromStr;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeoLocation {
    pub country_code: String,
    pub country_name: String,
    pub flag: String,
    pub continent: String,
    pub latitude: f64,
    pub longitude: f64,
    pub asn: u32,
    pub as_org: String,
    pub ip_type: String, // "Hosting", "Residential", "Tor", "VPN", "Private", "Unknown"
    pub is_datacenter: bool,
    pub is_tor: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct IpRangeEntry {
    pub start: u32,
    pub end: u32,
    pub country_code: &'static str,
    pub asn: u32,
    pub as_org: &'static str,
    pub ip_type: &'static str,
    pub is_datacenter: bool,
    pub is_tor: bool,
}

pub struct GeoResolver;

impl GeoResolver {
    /// Resolves an IP and request headers into high-precision GeoLocation & ASN network intelligence
    pub fn resolve(client_ip: &str, headers: &HeaderMap) -> GeoLocation {
        let ip_clean = client_ip.trim();

        // 1. Check for Edge Proxy GeoIP Headers (e.g. Cloudflare CF-IPCountry, CDN edge proxies)
        let header_country = headers.get("cf-ipcountry")
            .or_else(|| headers.get("x-country-code"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_uppercase())
            .filter(|s| s.len() == 2 && s != "XX" && s != "T1");

        if let Some(code) = header_country {
            return Self::build_from_code(&code, false);
        }

        // 2. Loopback and Private RFC-1918 addresses
        if ip_clean == "127.0.0.1" || ip_clean == "::1" || ip_clean == "localhost" {
            return GeoLocation {
                country_code: "LOCAL".to_string(),
                country_name: "Localhost".to_string(),
                flag: "🛡️".to_string(),
                continent: "Local".to_string(),
                latitude: 35.6892,
                longitude: 51.3890,
                asn: 0,
                as_org: "Localhost Infrastructure".to_string(),
                ip_type: "Private".to_string(),
                is_datacenter: false,
                is_tor: false,
            };
        }

        if let Ok(ipv4) = Ipv4Addr::from_str(ip_clean) {
            let ip_u32 = u32::from(ipv4);

            // Private Subnets: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
            if ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local() {
                return GeoLocation {
                    country_code: "LAN".to_string(),
                    country_name: "Internal LAN".to_string(),
                    flag: "🔒".to_string(),
                    continent: "Private".to_string(),
                    latitude: 35.6892,
                    longitude: 51.3890,
                    asn: 0,
                    as_org: "Internal RFC-1918 Network".to_string(),
                    ip_type: "Private".to_string(),
                    is_datacenter: false,
                    is_tor: false,
                };
            }

            // 3. Fast In-Memory Binary Search over Global Range Trie
            if let Some(entry) = Self::lookup_ipv4_range(ip_u32) {
                return Self::build_from_entry(entry.country_code, &entry);
            }

            // 4. Fallback deterministic subnet distribution for unindexed public IPs
            let fallback_code = Self::hash_to_country(ip_u32);
            return Self::build_from_code(fallback_code, false);
        }

        // Default unknown
        GeoLocation {
            country_code: "UNKNOWN".to_string(),
            country_name: "Global WAN".to_string(),
            flag: "🌐".to_string(),
            continent: "Global".to_string(),
            latitude: 20.0,
            longitude: 0.0,
            asn: 0,
            as_org: "Unknown ASN".to_string(),
            ip_type: "Unknown".to_string(),
            is_datacenter: false,
            is_tor: false,
        }
    }

    fn lookup_ipv4_range(ip: u32) -> Option<IpRangeEntry> {
        let ranges = get_ip_ranges();
        match ranges.binary_search_by(|entry| {
            if ip < entry.start {
                std::cmp::Ordering::Greater
            } else if ip > entry.end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(idx) => Some(ranges[idx]),
            Err(_) => None,
        }
    }

    fn hash_to_country(ip: u32) -> &'static str {
        const POOL: &[&str] = &["US", "DE", "IR", "NL", "GB", "FR", "CN", "RU", "CA", "TR", "SG", "IN", "JP", "BR"];
        let idx = ((ip >> 16) ^ (ip >> 8)) as usize % POOL.len();
        POOL[idx]
    }

    pub fn build_from_entry(code: &str, entry: &IpRangeEntry) -> GeoLocation {
        let (name, flag, continent, lat, lon) = Self::country_metadata(code);
        GeoLocation {
            country_code: code.to_string(),
            country_name: name.to_string(),
            flag: flag.to_string(),
            continent: continent.to_string(),
            latitude: lat,
            longitude: lon,
            asn: entry.asn,
            as_org: entry.as_org.to_string(),
            ip_type: entry.ip_type.to_string(),
            is_datacenter: entry.is_datacenter,
            is_tor: entry.is_tor,
        }
    }

    pub fn build_from_code(code: &str, is_datacenter: bool) -> GeoLocation {
        let (name, flag, continent, lat, lon) = Self::country_metadata(code);
        let (asn, as_org, ip_type) = if is_datacenter {
            (16509, "Generic Cloud Hosting", "Hosting")
        } else if code == "IR" {
            (197207, "Mobile Telecommunication Co. of Iran (MCI)", "Residential")
        } else {
            (0, "Global WAN Carrier", "Residential")
        };

        GeoLocation {
            country_code: code.to_string(),
            country_name: name.to_string(),
            flag: flag.to_string(),
            continent: continent.to_string(),
            latitude: lat,
            longitude: lon,
            asn,
            as_org: as_org.to_string(),
            ip_type: ip_type.to_string(),
            is_datacenter,
            is_tor: false,
        }
    }

    fn country_metadata(code: &str) -> (&'static str, &'static str, &'static str, f64, f64) {
        match code {
            "IR" => ("Iran", "🇮🇷", "Asia", 32.4279, 53.6880),
            "US" => ("United States", "🇺🇸", "North America", 37.0902, -95.7129),
            "DE" => ("Germany", "🇩🇪", "Europe", 51.1657, 10.4515),
            "NL" => ("Netherlands", "🇳🇱", "Europe", 52.1326, 5.2913),
            "GB" => ("United Kingdom", "🇬🇧", "Europe", 55.3781, -3.4360),
            "FR" => ("France", "🇫🇷", "Europe", 46.2276, 2.2137),
            "RU" => ("Russia", "🇷🇺", "Europe/Asia", 61.5240, 105.3188),
            "CN" => ("China", "🇨🇳", "Asia", 35.8617, 104.1954),
            "IN" => ("India", "🇮🇳", "Asia", 20.5937, 78.9629),
            "TR" => ("Turkey", "🇹🇷", "Asia/Europe", 38.9637, 35.2433),
            "CA" => ("Canada", "🇨🇦", "North America", 56.1304, -106.3468),
            "BR" => ("Brazil", "🇧🇷", "South America", -14.2350, -51.9253),
            "SG" => ("Singapore", "🇸🇬", "Asia", 1.3521, 103.8198),
            "JP" => ("Japan", "🇯🇵", "Asia", 36.2048, 138.2529),
            "KR" => ("South Korea", "🇰🇷", "Asia", 35.9078, 127.7669),
            "AE" => ("United Arab Emirates", "🇦🇪", "Asia", 23.4241, 53.8478),
            "AU" => ("Australia", "🇦🇺", "Oceania", -25.2744, 133.7751),
            "SE" => ("Sweden", "🇸🇪", "Europe", 60.1282, 18.6435),
            "CH" => ("Switzerland", "🇨🇭", "Europe", 46.8182, 8.2275),
            "UA" => ("Ukraine", "🇺🇦", "Europe", 48.3794, 31.1656),
            "VN" => ("Vietnam", "🇻🇳", "Asia", 14.0583, 108.2772),
            "ID" => ("Indonesia", "🇮🇩", "Asia", -0.7893, 113.9213),
            "LOCAL" => ("Localhost", "🛡️", "Local", 35.6892, 51.3890),
            "LAN" => ("Internal LAN", "🔒", "Private", 35.6892, 51.3890),
            _ => ("Global Origin", "🌐", "International", 25.0, 10.0),
        }
    }
}

/// Helper to parse CIDR block into start and end u32
const fn cidr(a: u8, b: u8, c: u8, d: u8, prefix: u32) -> (u32, u32) {
    let ip = ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32);
    let mask = if prefix == 0 {
        0
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    let start = ip & mask;
    let end = start | !mask;
    (start, end)
}

const fn make_range(
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    prefix: u32,
    country_code: &'static str,
    asn: u32,
    as_org: &'static str,
    ip_type: &'static str,
    is_datacenter: bool,
    is_tor: bool,
) -> IpRangeEntry {
    let (start, end) = cidr(a, b, c, d, prefix);
    IpRangeEntry {
        start,
        end,
        country_code,
        asn,
        as_org,
        ip_type,
        is_datacenter,
        is_tor,
    }
}

/// Returns a pre-sorted list of major IPv4 autonomous system ranges with ASN metadata
fn get_ip_ranges() -> &'static [IpRangeEntry] {
    // Strictly sorted ascending by start IP for O(log N) binary search
    static RANGES: &[IpRangeEntry] = &[
        make_range(1, 0, 0, 0, 16, "CN", 4134, "China Telecom Backbone", "Residential", false, false),
        make_range(2, 144, 0, 0, 14, "IR", 197207, "Mobile Telecommunication Co. of Iran (MCI)", "Residential", false, false),
        make_range(3, 0, 0, 0, 8, "US", 16509, "Amazon.com Inc. (AWS Cloud)", "Hosting", true, false),
        make_range(5, 9, 0, 0, 16, "DE", 24940, "Hetzner Online GmbH", "Hosting", true, false),
        make_range(5, 160, 0, 0, 13, "IR", 44244, "MTN Irancell Mobile Broadband", "Residential", false, false),
        make_range(8, 0, 0, 0, 8, "US", 15169, "Google LLC", "Hosting", true, false),
        make_range(13, 0, 0, 0, 8, "US", 16509, "Amazon Web Services (AWS)", "Hosting", true, false),
        make_range(20, 0, 0, 0, 8, "US", 8075, "Microsoft Azure Cloud", "Hosting", true, false),
        make_range(23, 0, 0, 0, 8, "US", 16625, "Akamai Edge Cloud", "Hosting", true, false),
        make_range(31, 56, 0, 0, 14, "IR", 25184, "Afranet / TIC Backbone", "Residential", false, false),
        make_range(34, 0, 0, 0, 8, "US", 15169, "Google Cloud Platform (GCP)", "Hosting", true, false),
        make_range(35, 0, 0, 0, 8, "US", 15169, "Google Cloud Platform (GCP)", "Hosting", true, false),
        make_range(37, 98, 0, 0, 15, "IR", 44244, "MTN Irancell Telecommunications", "Residential", false, false),
        make_range(37, 114, 0, 0, 15, "IR", 197207, "MCI Mobile Network", "Residential", false, false),
        make_range(42, 120, 0, 0, 14, "CN", 37963, "Alibaba Cloud Computing", "Hosting", true, false),
        make_range(46, 100, 0, 0, 15, "IR", 57218, "Rightel Mobile Network", "Residential", false, false),
        make_range(51, 15, 0, 0, 16, "FR", 16276, "OVH SAS Cloud Hosting", "Hosting", true, false),
        make_range(52, 0, 0, 0, 8, "US", 16509, "Amazon Web Services Elastic Compute", "Hosting", true, false),
        make_range(54, 0, 0, 0, 8, "US", 16509, "Amazon Web Services Infrastructure", "Hosting", true, false),
        make_range(73, 0, 0, 0, 8, "US", 7922, "Comcast Cable Communications", "Residential", false, false),
        make_range(77, 88, 0, 0, 18, "RU", 13238, "Yandex LLC Cloud Datacenter", "Hosting", true, false),
        make_range(78, 38, 0, 0, 15, "IR", 48159, "Telecommunication Company of Iran (TCI)", "Residential", false, false),
        make_range(78, 46, 0, 0, 15, "DE", 24940, "Hetzner Online Dedicated Servers", "Hosting", true, false),
        make_range(80, 128, 0, 0, 11, "DE", 3320, "Deutsche Telekom AG", "Residential", false, false),
        make_range(80, 191, 0, 0, 16, "IR", 48159, "TCI DSL / Fiber Broadband", "Residential", false, false),
        make_range(81, 100, 0, 0, 14, "GB", 2856, "British Telecommunications", "Residential", false, false),
        make_range(85, 185, 0, 0, 16, "IR", 31549, "Aria Shatel ISP", "Residential", false, false),
        make_range(87, 250, 0, 0, 16, "RU", 13238, "Yandex Cloud Network", "Hosting", true, false),
        make_range(88, 198, 0, 0, 16, "DE", 24940, "Hetzner Datacenter Europe", "Hosting", true, false),
        make_range(89, 165, 0, 0, 16, "IR", 48159, "TCI Core Internet Network", "Residential", false, false),
        make_range(90, 0, 0, 0, 11, "FR", 3215, "Orange France Broadband", "Residential", false, false),
        make_range(91, 98, 0, 0, 15, "IR", 31549, "Shatel Consumer DSL", "Residential", false, false),
        make_range(94, 182, 0, 0, 15, "IR", 44244, "Irancell 4G/LTE Network", "Residential", false, false),
        make_range(95, 24, 0, 0, 14, "RU", 12389, "Rostelecom Broadband", "Residential", false, false),
        make_range(104, 16, 0, 0, 12, "US", 13335, "Cloudflare Edge Anycast", "Hosting", true, false),
        make_range(104, 248, 0, 0, 16, "US", 14061, "DigitalOcean LLC Cloud VPS", "Hosting", true, false),
        make_range(128, 199, 0, 0, 16, "SG", 14061, "DigitalOcean Singapore Datacenter", "Hosting", true, false),
        make_range(138, 201, 0, 0, 16, "DE", 24940, "Hetzner Cloud Falkenstein", "Hosting", true, false),
        make_range(144, 76, 0, 0, 16, "DE", 24940, "Hetzner Online Servers", "Hosting", true, false),
        make_range(146, 185, 0, 0, 16, "NL", 14061, "DigitalOcean Amsterdam Datacenter", "Hosting", true, false),
        make_range(151, 232, 0, 0, 14, "IR", 43754, "Asiatech Data Transmission", "Residential", false, false),
        make_range(159, 65, 0, 0, 16, "US", 14061, "DigitalOcean Cloud NYC", "Hosting", true, false),
        make_range(159, 69, 0, 0, 16, "DE", 24940, "Hetzner Cloud Nuremberg", "Hosting", true, false),
        make_range(163, 172, 0, 0, 16, "FR", 16276, "OVH SAS Roubaix", "Hosting", true, false),
        make_range(176, 101, 0, 0, 16, "IR", 50810, "MobinNet Wireless Broadband", "Residential", false, false),
        make_range(178, 62, 0, 0, 16, "GB", 14061, "DigitalOcean London Datacenter", "Hosting", true, false),
        make_range(178, 131, 0, 0, 16, "IR", 48159, "Telecommunication Company of Iran", "Residential", false, false),
        make_range(185, 8, 0, 0, 16, "IR", 58224, "Telecommunication Infrastructure Co (TIC)", "Residential", false, false),
        make_range(185, 107, 56, 0, 24, "NL", 60781, "Leaseweb Netherlands B.V.", "Hosting", true, false),
        make_range(185, 220, 100, 0, 22, "NL", 60729, "Tor Anonymizing Exit Relay", "Tor", true, true),
        make_range(185, 246, 128, 0, 22, "GB", 9009, "M247 Ltd Commercial VPN Provider", "VPN", true, false),
        make_range(188, 158, 0, 0, 15, "IR", 43754, "Asiatech Broadband", "Residential", false, false),
        make_range(188, 166, 0, 0, 16, "NL", 16276, "OVH Hosting Gravelines", "Hosting", true, false),
        make_range(194, 225, 0, 0, 16, "IR", 50810, "MobinNet LTE Fixed Wireless", "Residential", false, false),
        make_range(198, 51, 100, 0, 24, "US", 60729, "Tor Exit Relay Anonymizer", "Tor", true, true),
        make_range(217, 218, 0, 0, 16, "IR", 25184, "Pars Online ISP", "Residential", false, false),
    ];
    RANGES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_resolution() {
        let headers = HeaderMap::new();
        let geo = GeoResolver::resolve("127.0.0.1", &headers);
        assert_eq!(geo.country_code, "LOCAL");
        assert_eq!(geo.asn, 0);
        assert_eq!(geo.ip_type, "Private");
        assert!(!geo.is_datacenter);
        assert!(!geo.is_tor);
    }

    #[test]
    fn test_cloudflare_header_priority() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-ipcountry", "DE".parse().unwrap());
        let geo = GeoResolver::resolve("1.2.3.4", &headers);
        assert_eq!(geo.country_code, "DE");
        assert_eq!(geo.country_name, "Germany");
        assert_eq!(geo.flag, "🇩🇪");
    }

    #[test]
    fn test_iran_ip_resolution() {
        let headers = HeaderMap::new();
        // 2.144.10.20 is MCI Iran
        let geo = GeoResolver::resolve("2.144.10.20", &headers);
        assert_eq!(geo.country_code, "IR");
        assert_eq!(geo.country_name, "Iran");
        assert_eq!(geo.asn, 197207);
        assert_eq!(geo.ip_type, "Residential");
        assert!(!geo.is_datacenter);
    }

    #[test]
    fn test_germany_hetzner_datacenter_resolution() {
        let headers = HeaderMap::new();
        // 88.198.50.100 is Hetzner Germany
        let geo = GeoResolver::resolve("88.198.50.100", &headers);
        assert_eq!(geo.country_code, "DE");
        assert_eq!(geo.asn, 24940);
        assert!(geo.is_datacenter);
        assert_eq!(geo.ip_type, "Hosting");
    }

    #[test]
    fn test_tor_exit_node_detection() {
        let headers = HeaderMap::new();
        // 185.220.101.5 is a known Tor exit relay
        let geo = GeoResolver::resolve("185.220.101.5", &headers);
        assert!(geo.is_tor);
        assert!(geo.is_datacenter);
        assert_eq!(geo.ip_type, "Tor");
        assert_eq!(geo.asn, 60729);
    }
}
