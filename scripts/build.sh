#!/bin/bash
set -e

echo "=========================================="
echo "EXECGUARD BUILD"
echo "=========================================="

# Verifica dependencias
command -v rustc >/dev/null 2>&1 || { echo "Rust nao instalado. Instale via rustup."; exit 1; }

# Instala target WASM se necessario
rustup target add wasm32-unknown-unknown 2>/dev/null || true

cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)

echo ""
echo "[1/3] Compilando modulo WASM..."
cd "$PROJECT_ROOT/execguard-wasm"
cargo build --target wasm32-unknown-unknown --release

# CORRECAO: Encontra o arquivo .wasm gerado (pode ter nome diferente)
echo ""
echo "[2/3] Localizando e copiando modulo WASM..."
WASM_FILE=$(find "$PROJECT_ROOT/execguard-wasm/target/wasm32-unknown-unknown/release" -name "*.wasm" | head -1)

if [ -z "$WASM_FILE" ]; then
    echo "ERRO: Arquivo .wasm nao encontrado!"
    echo "Conteudo do diretorio release:"
    ls -la "$PROJECT_ROOT/execguard-wasm/target/wasm32-unknown-unknown/release/"
    exit 1
fi

echo "WASM encontrado: $WASM_FILE"
cp "$WASM_FILE" "$PROJECT_ROOT/execguard-agent/execguard.wasm"
echo "Copiado para: $PROJECT_ROOT/execguard-agent/execguard.wasm"

echo ""
echo "[3/3] Compilando agente..."
cd "$PROJECT_ROOT/execguard-agent"
cargo build --release

echo ""
echo "=========================================="
echo "BUILD OK!"
echo "=========================================="
echo ""
echo "Para executar: ./scripts/test.sh"
