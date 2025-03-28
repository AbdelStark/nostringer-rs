# Benchmarking Guide

This document explains how to run and view the benchmarks for the nostringer library.

## Running Benchmarks Locally

### Prerequisites

To generate HTML reports with charts, you need gnuplot installed:

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install gnuplot
```

#### macOS
```bash
brew install gnuplot
```

#### Windows
Install gnuplot from [the official website](http://www.gnuplot.info/download.html) or via package managers like Chocolatey:
```bash
choco install gnuplot
```

### Running the Benchmarks

To run the benchmarks locally:

```bash
cargo bench
```

This will execute all benchmarks and generate a report at `target/criterion/report/index.html`.

To run a specific benchmark:

```bash
cargo bench --bench ring_signatures
```

## Viewing Benchmark Results

### Local Results

After running the benchmarks, open the HTML report in your browser:

```bash
# Linux/macOS
open target/criterion/report/index.html

# Windows
start target/criterion/report/index.html
```

The report includes line charts comparing the performance across different ring sizes and operations.

### GitHub Actions Results

The repository includes a GitHub Action workflow that runs benchmarks on each push to the main branch and pull request. 

To access these benchmark results:

1. Go to the GitHub repository
2. Click on the "Actions" tab
3. Select the "Benchmarks" workflow
4. Choose the most recent run
5. Scroll down to the "Artifacts" section
6. Download the "benchmark-html-report" artifact
7. Extract the ZIP file and open the `index.html` file in your browser

## Interpreting the Results

The benchmark results show the performance of the following operations with different ring sizes:

- `ring_signature_sign`: Time taken to sign a message
- `ring_signature_verify`: Time taken to verify a signature
- `ring_signature_sign_and_verify`: Time taken for both signing and verification

For each operation, we test with different ring sizes (2, 10, and 100 members) to demonstrate how performance scales with larger anonymity sets.

## Comparing Results

When running benchmarks across different environments or after code changes, consider:

1. **Hardware differences**: Performance will vary based on CPU, memory, and other factors
2. **Linear scaling**: Check if the operations scale linearly with ring size
3. **Relative performance**: Compare the relative differences between sign and verify operations

For the most accurate comparisons, use the same hardware and environment for all benchmark runs.

## Adding New Benchmarks

If you want to add new benchmarks:

1. Modify the `benches/ring_signatures.rs` file
2. Add your new benchmark function
3. Include it in the `criterion_group!` macro
4. Run `cargo bench` to validate 