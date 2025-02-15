![Build](https://github.com/apoelstra/rust-simplicity/workflows/Continuous%20integration/badge.svg)

# rust-simplicity
Under development....

# Minimum Supported Rust Version

The MSRV of this crate is **1.78.0**.

# Updating jets code

Some of the jet files in the library are auto-generated from Haskell code. These can be updated `update_jets.sh`. This requires the user has `cabal` and other necessary things that are required to build simplicity haskell. Instructions for those can be found in the simplicity repository.

This script also checks that the internal vendored version of simplicity has the same git hash as of the version from which we are auto-generating the code. If this is not the case, the script will fail. This is because we only vendor minimal required C simplicity code and not the entire simplicity repo.

# Benchmarking

There are two sets of benchmarks in this codebase. First, there is the `jets-bench`
sub-crate which uses criterion to collect statistics about jet performance. These
benchmarks are specifically targeted at the C jets and are intended to estimate
consensus costs.

See `jets-bench/README.md` for information about running these benchmarks.

The second set of benchmarks are benchmarks for this library's performance. These
are used to track performance of this library itself. These can be run with

```
RUSTFLAGS=--cfg=bench cargo +nightly bench
```

The custom `cfg` flag is used to prevent nightly-only code from polluting ordinary
code.
