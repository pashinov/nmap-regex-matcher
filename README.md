# nmap-regex-matcher

Matches HTTP requests against ~9500 regex patterns from nmap-service-probes.

## Build

```bash
cargo build --release
```

## Input data

**Patterns** — nmap-service-probes file:

```
https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes
```

**HTTP corpus** — JSON files from WAF Comparison Project:

```
https://downloads.openappsec.io/waf-comparison-project/legitimate.zip
https://downloads.openappsec.io/waf-comparison-project/malicious.zip
```

## Usage

```bash
./target/release/nmap-regex-matcher run \
  --probes data/nmap-service-probes \
  --corpus data/legitimate/Legitimate \
  --corpus data/malicious/Malicious
```

### Options

| Flag        | Description                                                         | Default   |
|-------------|---------------------------------------------------------------------|-----------|
| `--probes`  | Path to nmap-service-probes file                                    | required  |
| `--corpus`  | Directory with JSON request files (can be specified multiple times) | required  |
| `--limit`   | Maximum number of requests to process                               | 100 000   |
| `--threads` | Number of worker threads                                            | all cores |

### Examples

Quick test with 1000 requests and 4 threads:

```bash
./target/release/nmap-regex-matcher run \
  --probes data/nmap-service-probes \
  --corpus data/legitimate/Legitimate \
  --limit 1000 \
  --threads 4
```

Full run on ~1M requests:

```bash
./target/release/nmap-regex-matcher run \
  --probes data/nmap-service-probes \
  --corpus data/legitimate/Legitimate \
  --corpus data/malicious/Malicious \
  --limit 1100000
```

## Benchmarks

100k requests, 9504 patterns, AMD Ryzen 9 9950X (16 cores / 32 threads).

| Threads | Throughput (req/s) | Speedup | Elapsed |
|--------:|-------------------:|--------:|--------:|
|       1 |            3,753.8 |    1.0x |  26.64s |
|       4 |           12,470.8 |    3.3x |   8.02s |
|       8 |           14,896.1 |    4.0x |   6.71s |
|      16 |           24,108.4 |    6.4x |   4.15s |
|      32 |           17,539.0 |    4.7x |   5.70s |
