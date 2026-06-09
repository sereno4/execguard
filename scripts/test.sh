#!/bin/bash
set -e

cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)

echo "=========================================="
echo "EXECGUARD TEST SCRIPT"
echo "=========================================="

# Verifica se modulo WASM existe
if [ ! -f "$PROJECT_ROOT/execguard-agent/execguard.wasm" ]; then
    echo "Modulo WASM nao encontrado. Executando build primeiro..."
    bash "$PROJECT_ROOT/scripts/build.sh"
fi

cd "$PROJECT_ROOT/execguard-agent"

echo ""
echo "Executando agente com eventos de teste..."
echo ""
cargo run --release

echo ""
echo "=========================================="
echo "TESTE CONCLUIDO"
echo "=========================================="
