#!/bin/bash
set -e

echo "=========================================="
echo "EXECGUARD eBPF BUILD"
echo "=========================================="

cd "$(dirname "$0")"

# USA EXPLICITAMENTE o cargo do usuario dev
export CARGO_HOME="/home/dev/.cargo"
export RUSTUP_HOME="/home/dev/.rustup"
export PATH="/home/dev/.cargo/bin:$PATH"

# Forca toolchain explicita
export RUSTUP_TOOLCHAIN="stable"

echo "Cargo: $(which cargo)"
echo "Rustc: $(which rustc)"
echo "Version: $(rustc --version)"

if ! command -v cargo &> /dev/null; then
    echo "ERRO: cargo nao encontrado"
    exit 1
fi

rustup component add rust-src --toolchain nightly 2>/dev/null || true
rustup target add bpfel-unknown-none 2>/dev/null || true

echo ""
echo "[1/2] Compilando eBPF program..."
cd execguard-ebpf
cargo +nightly build --target=bpfel-unknown-none -Z build-std=core

echo ""
echo "[2/2] Compilando loader userspace..."
cd ..
cargo build --release

echo ""
echo "=========================================="
echo "BUILD OK!"
echo "=========================================="
ls -la target/release/execguard-loader 2>/dev/null || true
