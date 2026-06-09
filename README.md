ExecGuard

Runtime security pipeline using eBPF telemetry and WebAssembly policy execution.

ExecGuard is an experimental security platform that captures Linux process execution events through eBPF and evaluates them inside sandboxed WebAssembly modules.

The architecture separates event collection from policy execution, allowing security rules to be updated independently from the kernel instrumentation layer.

Architecture
Features
eBPF-based process monitoring
Sandboxed policy execution with WASM
Runtime risk scoring
JSON security events
Async Rust pipeline
Hot-swappable policy layer
Repository Structure
execguard/
├── execguard-ebpf/
├── execguard-agent/
├── execguard-wasm/
├── scripts/
└── docs/
Detection Rules
Rule	Description
BANNED_BINARY	Blacklisted executable
TMP_EXECUTION	Execution from /tmp
COMM_MISMATCH	Process name mismatch
REVERSE_SHELL	Reverse shell indicators
Example Event
{
  "pid": 1234,
  "uid": 1000,
  "comm": "bash",
  "file": "/tmp/nc -e /bin/bash",
  "risk_score": 10
}
Performance
Metric	Value
WASM latency	50-130 µs
Estimated throughput	>10k events/s
WASM memory	64 KB
WASM binary size	~15 KB
Current Status
Component	Status
WASM Engine	✅
Event Simulation	✅
Aya Loader	✅
eBPF Compilation	✅
Native Linux Validation	Pending
Limitations

Full eBPF execution requires a native Linux kernel.

WSL2 is supported for development and compilation but does not provide all kernel capabilities required for runtime validation.

Roadmap
Native Linux validation
Stateful correlation engine
RocksDB-backed storage
Hot reload of WASM modules
Prometheus metrics
OpenTelemetry integration
License

MIT
