# Benchmarks

This document provides detailed information about performance benchmarks for the nostringer ring signature library.

## Running Benchmarks

You can run the benchmarks yourself using Criterion:

```bash
# Run all benchmarks
cargo bench

# Run a specific benchmark
cargo bench --bench ring_signatures -- sign_small

# Run with HTML report generation
cargo bench --bench ring_signatures
```

After running benchmarks, HTML reports are generated in `target/criterion/report/index.html`.

## Benchmark Categories

The benchmarks test various operations with different ring sizes:

### Sign Operation

Tests the performance of creating a ring signature:

- `sign_small`: Ring with 2 members
- `sign_medium`: Ring with 10 members
- `sign_large`: Ring with 100 members

### Verify Operation

Tests the performance of verifying a ring signature:

- `verify_small`: Ring with 2 members
- `verify_medium`: Ring with 10 members
- `verify_large`: Ring with 100 members

### End-to-End Performance

Tests the combined sign and verify operations:

- `sign_verify_small`: Ring with 2 members
- `sign_verify_medium`: Ring with 10 members
- `sign_verify_large`: Ring with 100 members

### Binary vs. Hex API Performance

Tests the performance difference between the binary and hex string APIs:

- `sign_binary_vs_hex_small`: Ring with 2 members
- `sign_binary_vs_hex_medium`: Ring with 10 members
- `verify_binary_vs_hex_small`: Ring with 2 members
- `verify_binary_vs_hex_medium`: Ring with 10 members

## Latest Results

Here are the latest benchmark results measured on a MacBook Pro M1 Max:

| Operation       | Ring Size   | Execution Time (Median) |
| --------------- | ----------- | ----------------------- |
| **Sign**        | 2 members   | 204.75 µs               |
| **Sign**        | 10 members  | 897.76 µs               |
| **Sign**        | 100 members | 13.31 ms                |
| **Verify**      | 2 members   | 166.83 µs               |
| **Verify**      | 10 members  | 847.23 µs               |
| **Verify**      | 100 members | 12.71 ms                |
| **Sign+Verify** | 2 members   | 370.41 µs               |
| **Sign+Verify** | 10 members  | 1.76 ms                 |
| **Sign+Verify** | 100 members | 25.02 ms                |

### API Performance Comparison

| Operation  | API Type | Ring Size  | Time     | Speedup |
| ---------- | -------- | ---------- | -------- | ------- |
| **Sign**   | Hex      | 2 members  | 225.1 µs | -       |
| **Sign**   | Binary   | 2 members  | 204.8 µs | 1.10x   |
| **Sign**   | Hex      | 10 members | 985.3 µs | -       |
| **Sign**   | Binary   | 10 members | 897.8 µs | 1.09x   |
| **Verify** | Hex      | 2 members  | 182.4 µs | -       |
| **Verify** | Binary   | 2 members  | 166.8 µs | 1.09x   |
| **Verify** | Hex      | 10 members | 922.6 µs | -       |
| **Verify** | Binary   | 10 members | 847.2 µs | 1.09x   |

These results show that the binary API provides approximately 10% better performance by avoiding hex encoding/decoding overhead.

## Interpretation

### Linear Scaling

The time complexity of both signing and verification operations scales linearly with the ring size. This is expected as the algorithm needs to perform one calculation per ring member.

### Performance Considerations

- For small rings (2-10 members), performance is very good with sub-millisecond times
- For medium rings (10-100 members), performance remains reasonable in the millisecond range
- For large rings (100+ members), consider the performance impact when designing your application

### Hardware Impact

Performance will vary based on CPU architecture and speed. The benchmarks above were performed on:

- **Model:** MacBook Pro (Identifier: `MacBookPro18,2`)
- **CPU:** Apple M1 Max
- **Cores:** 10
- **RAM:** 64 GB
- **Architecture:** `arm64`
- **Operating System:** macOS 14.7 (Build `23H124`)

## Conclusion

The nostringer library provides excellent performance for most practical ring sizes. The binary API offers additional performance benefits for high-throughput applications.

For rings with more than 100 members, consider whether the increased anonymity set is worth the performance trade-off.
