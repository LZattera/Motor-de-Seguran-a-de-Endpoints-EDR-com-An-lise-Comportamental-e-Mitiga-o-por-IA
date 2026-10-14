# Contexto do Projeto: EDR Agent (Endpoint Detection and Response)

## Arquitetura Base
- **Stack:** C# (.NET 10.0), Worker Service. (Código-alvo é net10.0, não .NET 8.)
- **Padrão de Projeto:** Clean Architecture simplificada.
- **Objetivo:** Monitorar processos (Kernel) e tráfego de rede localmente de forma ultra-performática, atuando como um Daemon/Serviço.
- **Entrypoint:** `Worker` coordena `NetworkSniffer` (produtor) e `EdrAgentMonitor` (kernel, task LongRunning); `TelemetryConsumerService` consome o canal.

## Regras de Código (Strict Rules)
1. **Performance:** Utilize `System.Threading.Channels` para transferir dados entre produtores (coletores de eventos) e consumidores (envio de logs). Evite bloquear a thread principal (Thread Pool starvation).
2. **Bibliotecas Homologadas:** 
   - `Microsoft.Diagnostics.Tracing.TraceEvent` (para captura de processos no SO).
   - `SharpPcap` (para packet sniffing em modo promíscuo).
   - `Grpc.Net.Client` e `Google.Protobuf` (para comunicação).
3. **Resiliência:** O agente não pode consumir mais do que 50MB de RAM. Use `BoundedChannels` com `DropOldest` caso a ingestão de pacotes supere o envio.
4. **Tratamento de Exceções:** Nunca encerre o serviço principal por falhas na leitura de pacotes. Faça log da exceção e continue a escuta.

## Invariantes do Buffer
- `TelemetryBufferService`: bounded 100.000, `DropOldest`, single reader / multi-writer; contagem de descartados atomica.
- `TryPublish` O(1) e nunca bloqueia o produtor.
- O consumidor drena até 500 eventos a cada 100ms; envio gRPC ainda não implementado (placeholder).

## Segurança (fail-closed)
- mTLS com TLS 1.3 e pinning da CA privada; config inválida lança exceção em `MtlsChannelFactory.Create()`.
- Comandos de mitigação: assinatura ECDSA P-256 sobre os bytes exatos do payload; allowlist de `key_id`; validação de `target_agent_id`, janela de validade com skew/lifetime; anti-replay.
- Executor padrão `DryRun`; `Enforce` executa `powershell.exe` absoluto com `-EncodedCommand` (Base64 UTF-16LE) e `-ExecutionPolicy Restricted`.
- `ReplayCache` capacidade 10.000 (fail-closed quando cheio).

## Comandos / Ambiente
- Build: `dotnet build EdrAgentMonitor.csproj` | Testes: `dotnet test tests/EdrAgentMonitor.Tests/EdrAgentMonitor.Tests.csproj`
- Teste focalizado: `--filter "FullyQualifiedName~ClasseOuMetodo"`
- Run: `dotnet run --project EdrAgentMonitor.csproj` (requer elevação/Npcap no Windows)
- PKI dev: `.\scripts\New-DevPki.ps1` (corrigido para usar `--file` no .NET 10). `dotnet run scripts\DevPki.cs` inicia o agente, não gera certificados.
- Secrets (senha do PFX, AgentId) via user-secrets; `certs/` gitignored.

## Notas para futuras análises (evitar reexplorar)
- `csproj` exclui `tests/`, `scripts/` e `certs/` do binário principal.
- `IgnoredPort = 5001` do sniffer deve permanecer alinhado a `ServerEndpoint` (default https://localhost:5001).
- O monitor de kernel usa `TraceEventSession` em `using`; `Stop()` desbloqueia `Source.Process()`; campo `_session` é anulado após saída.
- O cliente gRPC é gerado no build a partir de `Protos/edr_telemetry.proto`, mas não há chamada de cliente registrada no DI.
- `MitigationExecutorTests` em modo `Enforce` invoca o PowerShell real do Windows.
- `FixedTimeProvider` está no arquivo de testes do verificador para reutilização.
- Ausência de captura em execução costuma indicar falta de elevação/Npcap, não erro de código.

## Stack Incompatibilidades Conhecidas
- Windows apenas (ETW, Npcap, Windows PowerShell). Alvo é .NET 10, não 8, apesar de notas antigas.