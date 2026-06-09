ExecGuard

ExecGuard é uma plataforma experimental de detecção de ameaças construída em Rust que combina eBPF para observabilidade kernel-level com WebAssembly (WASM) para execução segura de políticas de segurança em runtime.

O projeto explora uma arquitetura moderna inspirada em agentes EDR, onde a captura de eventos do sistema operacional é desacoplada da lógica de detecção através de módulos WASM carregados dinamicamente.

Objetivos
Capturar eventos de execução de processos diretamente do kernel usando eBPF
Processar eventos em userspace com baixo overhead
Executar regras de detecção em sandbox WASM
Permitir atualização de políticas sem recompilar o agente
Demonstrar integração entre Linux Observability, Runtime Security e WebAssembly
Arquitetura
┌─────────────────────────────────────────────────────────────┐
│                       KERNEL SPACE                          │
├─────────────────────────────────────────────────────────────┤
│ eBPF (Aya)                                                  │
│ • tracepoints                                               │
│ • syscall monitoring                                        │
│ • event collection                                          │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                     USERSPACE AGENT                         │
├─────────────────────────────────────────────────────────────┤
│ Aya Loader                                                  │
│ • ring buffer consumer                                      │
│ • event normalization                                       │
│ • async processing                                          │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                    WASM POLICY ENGINE                       │
├─────────────────────────────────────────────────────────────┤
│ Wasmtime Runtime                                            │
│ • enrich                                                    │
│ • correlate                                                 │
│ • score                                                     │
│ • alert generation                                          │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                      OUTPUT LAYER                           │
├─────────────────────────────────────────────────────────────┤
│ JSON Events                                                 │
│ Security Alerts                                             │
│ Metrics                                                     │
└─────────────────────────────────────────────────────────────┘
Principais Características
Runtime Security

Detecção baseada em comportamento de processos:

Execução de binários proibidos
Execução em diretórios temporários
Inconsistência entre processo e executável
Padrões de reverse shell
Scoring de risco em tempo real
WASM-Based Detection Engine

A lógica de detecção é executada dentro de módulos WebAssembly:

Isolamento de memória
Atualização independente do agente
Portabilidade
Extensibilidade por plugins
Rust End-to-End

Todo o pipeline é implementado em Rust:

Memory safety
Concorrência segura
Baixa latência
Overhead reduzido
Estado Atual
Componente	Status
WASM Policy Engine	✅ Funcional
Runtime Wasmtime	✅ Funcional
Event Processing	✅ Funcional
Threat Scoring	✅ Funcional
eBPF Program	✅ Compila
Aya Loader	✅ Compila
eBPF Runtime Validation	⏳ Requer Linux nativo
Hot Reload WASM	🚧 Planejado
Persistent State	🚧 Planejado
Benchmark Suite	🚧 Planejado
Roadmap
Fase 1
eBPF real em Linux nativo
Ring buffer pipeline completo
Integração eBPF → WASM
Fase 2
Persistência com RocksDB
Correlação temporal
Histórico de processos
Fase 3
Hot-swap de módulos WASM
Policy marketplace
Regras carregadas dinamicamente
Fase 4
Exportação Prometheus
Dashboard Grafana
Integração SIEM
Tecnologias
Rust
eBPF
Aya
Wasmtime
WebAssembly
Tokio
Serde
Linux Tracepoints
Resultados Iniciais
Latência WASM: ~50–130 µs
Módulo WASM: ~15 KB
Heap WASM: 64 KB
Throughput estimado: >10k eventos/s
