// Derived from nmaprs v0.1.1 (https://github.com/MenkeTechnologies/nmaprs)
// Original license: MIT OR Apache-2.0
// Changes: removed networking/TLS/async code, fixed regex flag parsing (s/i flags)

use std::path::Path;

use anyhow::{Context, Result};
use regex::bytes::Regex;

#[derive(Debug)]
pub struct ServiceMatch {
    pub service_name: String,
    pub regex: Regex,
    pub soft: bool,
}

/// Inclusive port ranges `(lo, hi)` from Nmap `ports` / `sslports` lines.
pub type PortRanges = Vec<(u16, u16)>;

#[derive(Debug)]
pub struct TcpProbe {
    pub name: String,
    pub payload: Vec<u8>,
    pub totalwait_ms: u64,
    pub rarity: u8,
    /// `None` ⇒ probe may run against any port (Nmap default when `ports` omitted for some probes).
    pub ports: Option<PortRanges>,
    pub sslports: Option<PortRanges>,
    pub matches: Vec<ServiceMatch>,
}

#[derive(Debug)]
pub struct UdpProbe {
    pub name: String,
    pub payload: Vec<u8>,
    pub totalwait_ms: u64,
    pub rarity: u8,
    pub ports: Option<PortRanges>,
    pub matches: Vec<ServiceMatch>,
}

#[derive(Debug, Default)]
pub struct ServiceProbes {
    pub tcp: Vec<TcpProbe>,
    pub udp: Vec<UdpProbe>,
}

pub fn load_service_probes(path: &Path) -> Result<ServiceProbes> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    parse_probes(&text).context("parse nmap-service-probes")
}

fn parse_probes(text: &str) -> Result<ServiceProbes> {
    let mut out = ServiceProbes::default();
    let mut cur_tcp: Option<TcpProbe> = None;
    let mut cur_udp: Option<UdpProbe> = None;

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("Exclude ") {
            continue;
        }

        if let Some(rest) = line.strip_prefix("Probe TCP ") {
            if let Some(p) = cur_udp.take() {
                out.udp.push(p);
            }
            if let Some(p) = cur_tcp.take() {
                out.tcp.push(p);
            }
            let (name, payload) = parse_probe_tcp_line(rest)?;
            cur_tcp = Some(TcpProbe {
                name,
                payload,
                totalwait_ms: 6000,
                rarity: 5,
                ports: None,
                sslports: None,
                matches: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = line.strip_prefix("Probe UDP ") {
            if let Some(p) = cur_tcp.take() {
                out.tcp.push(p);
            }
            if let Some(p) = cur_udp.take() {
                out.udp.push(p);
            }
            let (name, payload) = parse_probe_udp_line(rest)?;
            cur_udp = Some(UdpProbe {
                name,
                payload,
                totalwait_ms: 6000,
                rarity: 5,
                ports: None,
                matches: Vec::new(),
            });
            continue;
        }

        if let Some(p) = cur_tcp.as_mut() {
            if apply_probe_line_tcp(line, p)? {
                continue;
            }
        }
        if let Some(p) = cur_udp.as_mut() {
            if apply_probe_line_udp(line, p)? {
                continue;
            }
        }
    }

    if let Some(p) = cur_udp.take() {
        out.udp.push(p);
    }
    if let Some(p) = cur_tcp.take() {
        out.tcp.push(p);
    }

    Ok(out)
}

fn apply_probe_line_tcp(line: &str, p: &mut TcpProbe) -> Result<bool> {
    if let Some(ms) = line.strip_prefix("totalwaitms ") {
        if let Ok(n) = ms.trim().parse::<u64>() {
            p.totalwait_ms = n;
        }
        return Ok(true);
    }
    if let Some(r) = line.strip_prefix("rarity ") {
        if let Ok(n) = r.trim().parse::<u8>() {
            p.rarity = n;
        }
        return Ok(true);
    }
    if let Some(rest) = line.strip_prefix("ports ") {
        p.ports = parse_port_ranges_list(rest);
        return Ok(true);
    }
    if let Some(rest) = line.strip_prefix("sslports ") {
        p.sslports = parse_port_ranges_list(rest);
        return Ok(true);
    }
    if line.starts_with("match ") || line.starts_with("softmatch ") {
        if let Some(m) = parse_match_line(line)? {
            p.matches.push(m);
        }
        return Ok(true);
    }
    Ok(false)
}

fn apply_probe_line_udp(line: &str, p: &mut UdpProbe) -> Result<bool> {
    if let Some(ms) = line.strip_prefix("totalwaitms ") {
        if let Ok(n) = ms.trim().parse::<u64>() {
            p.totalwait_ms = n;
        }
        return Ok(true);
    }
    if let Some(r) = line.strip_prefix("rarity ") {
        if let Ok(n) = r.trim().parse::<u8>() {
            p.rarity = n;
        }
        return Ok(true);
    }
    if let Some(rest) = line.strip_prefix("ports ") {
        p.ports = parse_port_ranges_list(rest);
        return Ok(true);
    }
    if line.starts_with("match ") || line.starts_with("softmatch ") {
        if let Some(m) = parse_match_line(line)? {
            p.matches.push(m);
        }
        return Ok(true);
    }
    Ok(false)
}

fn parse_port_ranges_list(s: &str) -> Option<PortRanges> {
    let mut out = PortRanges::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let lo: u16 = a.trim().parse().ok()?;
            let hi: u16 = b.trim().parse().ok()?;
            out.push((lo.min(hi), lo.max(hi)));
        } else {
            let p: u16 = part.parse().ok()?;
            out.push((p, p));
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn parse_probe_tcp_line(rest: &str) -> Result<(String, Vec<u8>)> {
    let rest = rest.trim_start();
    let name_end = rest
        .find(char::is_whitespace)
        .ok_or_else(|| anyhow::anyhow!("Probe TCP: missing probe name"))?;
    let name = rest[..name_end].to_string();
    let qpart = rest[name_end..].trim_start();
    let payload = parse_q_field(qpart).unwrap_or_default();
    Ok((name, payload))
}

fn parse_probe_udp_line(rest: &str) -> Result<(String, Vec<u8>)> {
    let rest = rest.trim_start();
    let name_end = rest
        .find(char::is_whitespace)
        .ok_or_else(|| anyhow::anyhow!("Probe UDP: missing probe name"))?;
    let name = rest[..name_end].to_string();
    let qpart = rest[name_end..].trim_start();
    let payload = parse_q_field(qpart).unwrap_or_default();
    Ok((name, payload))
}

/// `q|payload|` — delimiter is the first byte after `q`.
fn parse_q_field(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_start();
    let rest = s.strip_prefix('q')?;
    let delim = rest.chars().next()?;
    let inner = rest.get(delim.len_utf8()..)?;
    let end = inner.find(delim)?;
    Some(decode_nmap_escape_bytes(&inner[..end]))
}

fn hex_nibble(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

fn decode_nmap_escape_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c as u8);
            continue;
        }
        match it.next() {
            Some('x') | Some('X') => {
                let a = it.next().unwrap_or('0');
                let b = it.next().unwrap_or('0');
                if let (Some(hi), Some(lo)) = (hex_nibble(a), hex_nibble(b)) {
                    out.push(hi << 4 | lo);
                }
            }
            Some('0') => out.push(0),
            Some('n') => out.push(b'\n'),
            Some('r') => out.push(b'\r'),
            Some('t') => out.push(b'\t'),
            Some('\\') => out.push(b'\\'),
            Some(o) => out.push(o as u8),
            None => {}
        }
    }
    out
}

fn parse_match_line(line: &str) -> Result<Option<ServiceMatch>> {
    let soft = line.starts_with("softmatch ");
    // `apply_probe_line_*` only calls here after `match ` / `softmatch ` prefix check.
    let rest = if soft {
        &line["softmatch ".len()..]
    } else {
        &line["match ".len()..]
    };
    let (service_token, after_svc) = split_first_token(rest);
    if service_token.is_empty() {
        return Ok(None);
    }
    let after_svc = after_svc.trim_start();
    let (pattern_src, tail) = match extract_m_delimited(after_svc) {
        Some(x) => x,
        None => return Ok(None),
    };
    // Matches nmap's C++ flag parsing from service_scan.cc:
    //   for (p = flags; *p != '\0'; p++) {
    //       if (*p == 'i') matchops_ignorecase = true;
    //       else if (*p == 's') matchops_dotall = true;
    //   }
    let flags_str: String = tail
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    let mut pat = String::new();
    if flags_str.contains('s') {
        pat.push_str("(?s)");
    }
    if flags_str.contains('i') {
        pat.push_str("(?i)");
    }
    pat.push_str(pattern_src);

    let regex = match Regex::new(&pat) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    Ok(Some(ServiceMatch {
        service_name: service_token.to_string(),
        regex,
        soft,
    }))
}

fn split_first_token(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    (&s[..end], &s[end..])
}

fn extract_m_delimited(rest: &str) -> Option<(&str, &str)> {
    let b = rest.as_bytes();
    if b.first().copied()? != b'm' {
        return None;
    }
    let delim = b.get(1).copied()? as char;
    let mut i = 2usize;
    let mut escaped = false;
    while i < b.len() {
        let c = b[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if c == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if c == delim as u8 {
            let pattern = std::str::from_utf8(&b[2..i]).ok()?;
            let tail = std::str::from_utf8(&b[i + 1..]).ok()?;
            return Some((pattern, tail));
        }
        i += 1;
    }
    None
}
