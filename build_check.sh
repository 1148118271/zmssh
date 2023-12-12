#!/bin/bash
set -e
echo format check
cargo fmt --all -- --check > /dev/null
echo done
echo
echo
echo clippy check
cargo clippy -- -D warnings > /dev/null
echo
echo
echo clippy all check
cargo clippy --all-features -- -D warnings > /dev/null
echo
echo
echo linux build check
cargo build --target x86_64-unknown-linux-gnu > /dev/null
echo done
echo
echo
echo wasm build check
cargo build --target wasm32-unknown-unknown > /dev/null
echo done
echo
echo
echo windows build check
cargo build --target x86_64-pc-windows-gnu > /dev/null
echo done
echo
echo
echo cargo test
cargo test --all-features -- --test-threads 1 > /dev/null
echo done