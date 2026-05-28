use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{Parser, Subcommand};
use rayon::prelude::*;
use regex_automata::{Input, meta::Cache};

use crate::models::{HttpRequest, Pattern};

#[allow(warnings)]
mod models;
#[allow(warnings)]
mod vscan;

fn main() -> anyhow::Result<()> {
    match App::parse().cmd {
        SubCmd::Run(cmd) => cmd.run(),
    }
}

#[derive(Parser)]
struct App {
    #[command(subcommand)]
    cmd: SubCmd,
}

#[derive(Subcommand)]
enum SubCmd {
    Run(RunCmd),
}

#[derive(Parser)]
struct RunCmd {
    #[arg(long)]
    probes: PathBuf,

    #[arg(long)]
    corpus: Vec<PathBuf>,

    #[arg(long, default_value_t = 100_000)]
    limit: usize,

    #[arg(long)]
    threads: Option<usize>,
}

impl RunCmd {
    fn run(self) -> anyhow::Result<()> {
        let patterns = load_patterns(&self.probes);

        let corpus_refs: Vec<&Path> = self.corpus.iter().map(|p| p.as_path()).collect();
        let requests = load_corpus(&corpus_refs, self.limit)?;

        let available_threads = std::thread::available_parallelism()?.get();

        let num_threads = self
            .threads
            .unwrap_or(available_threads)
            .min(available_threads);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .thread_name(|i| format!("regex-worker-{i}"))
            .build()?;

        let num_patterns = patterns.len();
        eprintln!(
            "Matching: {} requests × {num_patterns} patterns, {num_threads} threads",
            requests.len()
        );

        let chunk_size = requests.len().div_ceil(num_threads);

        let start = Instant::now();
        let total_matches: u64 = pool.install(|| {
            requests
                .par_chunks(chunk_size)
                .map(|chunk| {
                    let mut count = 0u64;

                    let mut caches: Vec<Cache> =
                        patterns.iter().map(|p| p.regex.create_cache()).collect();

                    for data in chunk {
                        let input = Input::new(data);
                        for (pat, cache) in patterns.iter().zip(caches.iter_mut()) {
                            if pat.regex.search_with(cache, &input).is_some() {
                                count += 1;
                            }
                        }
                    }

                    count
                })
                .sum()
        });
        let elapsed = start.elapsed();

        let throughput = requests.len() as f64 / elapsed.as_secs_f64();
        eprintln!("\n=== Results ===");
        eprintln!("Requests:    {}", requests.len());
        eprintln!("Patterns:    {num_patterns}");
        eprintln!("Total matches: {total_matches}");
        eprintln!("Elapsed:     {:.3}s", elapsed.as_secs_f64());
        eprintln!("Throughput:  {throughput:.1} req/s");

        Ok(())
    }
}

trait Normalize {
    fn normalize(&self) -> Vec<u8>;
}

impl Normalize for HttpRequest {
    fn normalize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(self.method.as_bytes());
        buf.push(b' ');
        buf.extend_from_slice(self.url.as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\n");
        for (k, v) in &self.headers {
            buf.extend_from_slice(k.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(v.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(b"\r\n");
        if let Some(body) = &self.data
            && !body.is_empty()
        {
            buf.extend_from_slice(body.as_bytes());
        }

        buf
    }
}

fn load_patterns(path: &Path) -> Vec<Pattern> {
    let probes = vscan::load_service_probes(path).expect("failed to parse nmap-service-probes");
    let mut patterns = Vec::new();

    for (probe_index, probe) in probes.tcp.iter().enumerate() {
        for m in &probe.matches {
            if let Ok(re) = regex_automata::meta::Regex::new(m.regex.as_str()) {
                patterns.push(Pattern {
                    service: m.service_name.clone(),
                    soft: m.soft,
                    regex: re,
                    probe_index,
                });
            }
        }
    }
    for (probe_index, probe) in probes.udp.iter().enumerate() {
        for m in &probe.matches {
            if let Ok(re) = regex_automata::meta::Regex::new(m.regex.as_str()) {
                patterns.push(Pattern {
                    service: m.service_name.clone(),
                    soft: m.soft,
                    regex: re,
                    probe_index: probes.tcp.len() + probe_index,
                });
            }
        }
    }

    patterns
}

fn load_corpus(dirs: &[&Path], limit: usize) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut entries = Vec::new();
    for dir in dirs {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.path().extension().is_some_and(|ext| ext == "json") {
                entries.push(entry);
            }
        }
    }
    entries.sort_by_key(|e| e.path());

    let mut requests = Vec::new();
    for entry in entries {
        if requests.len() >= limit {
            break;
        }

        let data = fs::read(entry.path())?;
        let reqs: Vec<HttpRequest> = serde_json::from_slice(&data)?;
        for req in reqs {
            if requests.len() >= limit {
                break;
            }
            requests.push(req.normalize());
        }
    }

    Ok(requests)
}
