use std::collections::BTreeMap;

use regex::bytes::Regex;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub data: Option<String>,
}

pub struct Pattern {
    pub service: String,
    pub soft: bool,
    pub regex: Regex,
    pub probe_index: usize,
}
