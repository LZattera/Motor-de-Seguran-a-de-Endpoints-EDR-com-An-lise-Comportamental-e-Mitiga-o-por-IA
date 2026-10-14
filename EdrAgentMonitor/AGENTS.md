# EdrAgentMonitor

.NET 10 Worker Service (EDR agent): captures kernel process events (ETW) and network packets, buffers them in a channel, and exposes mTLS + signed-command infrastructure for AI-driven mitigation.

## Commands
- Build agent: `dotnet build EdrAgentMonitor.csproj`
- Build with tests: `dotnet build EdrAgentMonitor.slnx`
- Test all: `dotnet test tests/EdrAgentMonitor.Tests/EdrAgentMonitor.Tests.csproj`
- Focused test: `dotnet test tests/EdrAgentMonitor.Tests/EdrAgentMonitor.Tests.csproj --filter "FullyQualifiedName~MitigationCommandVerifierTests"`
- Run agent (dev): `dotnet run --project EdrAgentMonitor.csproj` (uses launchSettings -> Development env)
- Generate dev PKI: `.\scripts\New-DevPki.ps1` (or `dotnet run --file scripts\DevPki.cs -- <outDir> <agentId> <serverDns> <validDays> <password>`)

Always use `--file` for `DevPki.cs`; `dotnet run scripts\DevPki.cs` starts the agent instead of generating certs.

## Runtime requirements
- Windows only: ETW kernel tracing, Npcap, Windows PowerShell host.
- Run elevated for ETW kernel provider + promiscuous capture; on failure the Worker logs and continues.
- Npcap must be installed; primary interface selected by default gateway (fallback: first IPv4 non-loopback).

## Data flow
- `Worker` starts `NetworkSniffer` (SharpPcap, promiscuous, BPF excludes port 5001) which publishes `NetworkEvent` structs into `TelemetryBufferService`.
- `NetworkSniffer.OnPacketArrival` only parses + `TryWrite`; no I/O on capture thread.
- `TelemetryConsumerService` drains up to 500 events / 100ms (placeholder console summary; gRPC send not wired).
- Kernel monitor (`EdrAgentMonitor`) runs ETW `Process` events on a dedicated `LongRunning` task; `monitor.Stop()` unblocks `Source.Process()`.

## Buffer invariants
- `TelemetryBufferService`: bounded 100_000, `DropOldest`, single reader, multi-writer; dropped count tracked atomically.
- `TryPublish` is O(1) and never blocks the producer.

## Security
- mTLS: `MtlsChannelFactory.Create()` throws on invalid config (fail-closed); TLS 1.3; private CA pinning; no public CA trust.
- Commands: verify ECDSA P-256 signature over exact payload bytes before parse; `key_id` allowlist; target agent id; validity window; anti-replay; fail-closed.
- Executor default `DryRun`; `Enforce` runs absolute `powershell.exe` with `-EncodedCommand` (UTF-16LE Base64) + `-ExecutionPolicy Restricted`, timeout captures output (8192 chars).
- `ReplayCache` capacity 10_000 (fail-closed when full, evicts expired when full).
- gRPC client generated at build from `Protos/edr_telemetry.proto`; no caller wired yet.

## Configuration
- `appsettings.json` `Security` section. Secrets (agent PFX password, `AgentId`) via user-secrets.
- Paths resolve relative to content root (project dir under `dotnet run`); `certs/` is gitignored.
- `AgentId` blank => machine name. Server endpoint default `https://localhost:5001`; sniffer ignores port 5001.
- `Executor.Mode`: `DryRun` / `Enforce`.

## Project boundaries
- Main project excludes `tests/`, `scripts/`, `certs/` from compile; put dev tooling there, not runtime source.
- `scripts/DevPki.cs` is a .NET 10 file-based app, not part of the agent binary.

## Testing notes
- xUnit, `net10.0`. `MitigationExecutorTests` Enforce cases shell out to Windows PowerShell (Windows-only).
- `FixedTimeProvider` lives inside the verifier test file for reuse.

## Non-negotiable rules
1. Use `System.Threading.Channels` between producers and consumers; never block the main thread.
2. Approved libs: TraceEvent (process capture), SharpPcap (sniffing), gRPC + protobuf (communication).
3. Stay <= 50MB RAM; bounded channels with `DropOldest` on overflow.
4. Never terminate on capture errors; log and continue listening.