#!/bin/bash
set -e

echo "=========================================="
echo "EXECGUARD eBPF TEST"
echo "=========================================="

cd "$(dirname "$0")"

if [ "$EUID" -ne 0 ]; then 
    echo "ERRO: eBPF requer root."
    echo "Execute: sudo ./test-ebpf.sh"
    exit 1
fi

# Binário está no workspace root target/release
LOADER_BIN="../target/release/execguard-loader"

if [ ! -f "$LOADER_BIN" ]; then
    echo "Binário não encontrado. Compilando..."
    ./build-ebpf.sh
fi

if [ ! -f "$LOADER_BIN" ]; then
    echo "ERRO: Binário do loader não encontrado"
    exit 1
fi

echo "Usando: $LOADER_BIN"

echo ""
echo "Capturando syscalls por 10 segundos..."
echo "Execute comandos em outro terminal: ls, cat, echo, bash"
echo ""

timeout 10 "$LOADER_BIN" --log-level info || true

echo ""
echo "=========================================="
echo "TESTE CONCLUIDO"
echo "=========================================="
