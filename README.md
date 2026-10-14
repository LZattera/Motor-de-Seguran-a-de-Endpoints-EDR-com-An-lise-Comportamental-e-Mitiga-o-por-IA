# Sentinel EDR: Autonomous Endpoint Detection & Response

Sistema de segurança cibernética (EDR) focado em detecção de ameaças em tempo real e resposta automatizada com IA em *edge* (air-gapped). O repositório contém atualmente o **agente de endpoint** em C#; os componentes de servidor/control plane fazem parte do roadmap e ainda não estão implementados neste repo.

## 🏗️ Arquitetura (visão)

Modelo distribuído de Edge Computing em duas camadas:

1. **Endpoint (Agente Local):** Daemon/Worker Service em C# (.NET 10) responsável pela interceptação de chamadas do Kernel e captura de pacotes de rede. ✅ implementado parcialmente.
2. **Control Plane (Servidor de Borda):** cluster conteinerizado para ingestão de telemetria, análise assíncrona via IA e despacho de mitigação. ⏳ roadmap.

## ✅ O Que Já Foi Implementado (Agente)

### 1. Agente EDR (C# / .NET 10 Worker Service)
- **Monitorização de Kernel:** interceptação em tempo real de criação de processos via `Microsoft.Diagnostics.Tracing.TraceEvent`.
- **Packet Sniffing:** captura em modo promíscuo com `SharpPcap` e filtro BPF (exclui a porta 5001 do canal próprio).
- **Otimização de Memória (Producer-Consumer):** `System.Threading.Channels` com `BoundedChannel` (100.000, `DropOldest`), mantendo baixo uso de RAM/CPU.

### 2. Comunicação e Contratos
- **Contrato gRPC:** `Protos/edr_telemetry.proto` (bidirecional `StreamTelemetry`) e cliente gerado no build via `Grpc.Tools`.
- **Status:** a chamada de streaming e a ingestão de telemetria **ainda não estão ligadas** no agente (só infraestrutura). Tooling de PKI/mTLS e validação de comandos já existem.

### 3. Segurança do Canal de Mitigação
- **mTLS:** `MtlsChannelFactory` com TLS 1.3 e pinning da CA privada (fail-closed).
- **Comandos assinados:** `MitigationCommandVerifier` valida ECDSA P-256 sobre os bytes exatos do payload, `key_id`, `target_agent_id`, janela de validade e anti-replay.
- **Executor:** `MitigationExecutor` padrão `DryRun`; `Enforce` executa PowerShell via `-EncodedCommand` (Base64 UTF-16LE) com timeout e captura truncada.

### 4. Dev PKI (scripts)
- `scripts/DevPki.cs` (app baseado em arquivo do .NET 10) gera CA, certs mTLS e chaves de assinatura.
- `scripts/New-DevPki.ps1` cria `certs/` e grava a senha no user-secrets.

## 🚀 Roadmap / Próximos Passos

### Fase 2: Ingestão e Processamento (servidor) — não implementado
- [ ] **Gateway gRPC (.NET / ASP.NET Core):** servidor que receba o streaming bidirecional do agente e faça *produce* de alta taxa para Redpanda/Kafka.
- [ ] **Worker de IA (.NET):** *consumer* do Redpanda, conversão de logs para JSON e acionamento do webhook do n8n.
- [ ] **Rastreamento de sessões gRPC ativas:** garantir que o comando de mitigação volte para a máquina correta.

### Fase 3: Orquestração e Resposta Autônoma
- [ ] **Pipeline RAG no n8n:** fluxo que recebe telemetria, injeta *system prompt* de segurança e obtém script do Ollama.
- [ ] **Motor de Execução (agente):** ligar o streaming gRPC no agente para consumir comandos e acionar `MitigationCommandHandler`/`MitigationExecutor`.
- [ ] **Envio de telemetria:** conectar `TelemetryConsumerService` ao canal gRPC (hoje é saída de console).
- [ ] **Envio de *ProcessLog*:** hoje o monitor de Kernel só imprime; canalizar para o buffer gRPC.

### Fase 4: Infraestrutura e Observabilidade
- [ ] **Docker Compose:** Redpanda, PostgreSQL + pgvector, Ollama (Phi-3) e n8n (arquivos não presentes neste repo).
- [ ] **Painel de Comando (Dashboard):** frontend reativo (SignalR/React) ou móvel (Flutter).
- [ ] **Service Windows:** instalação como serviço do Windows (`sc create`/NSSM) e hardening de privileges.
- [ ] **Kernel monitor robusto:** tratar restart da sessão ETW; hoje é uma execução única.

### Higiene / qualidade (curto prazo)
- [ ] **Tests para `NetworkSniffer`/pipeline:** hoje só segurança é testada.
- [ ] **Revisar target framework:** está em .NET 10; antigas notas citavam .NET 8 (rotulado).
- [ ] **PFX password / certs:** gerar PKI de dev antes de rodar o agente.

## 🛠️ Como Rodar o Agente

Requisitos: Windows, .NET 10 SDK, Npcap instalado, execução elevada.

```powershell
cd EdrAgentMonitor
# 1) PKI de desenvolvimento
.\scripts\New-DevPki.ps1
# 2) Build
dotnet build EdrAgentMonitor.csproj
# 3) Testes
dotnet test tests/EdrAgentMonitor.Tests/EdrAgentMonitor.Tests.csproj
# 4) Run (dev)
dotnet run --project EdrAgentMonitor.csproj
```

> Observação: `dotnet run scripts\DevPki.cs` (sem `--file`) **inicia o agente** em vez de gerar certificados.

## 📁 Estrutura do Projeto

```
EdrAgentMonitor/
  AGENTS.md            # guia para agentes de IA/devs
  CONTEXT.md           # contexto resumido
  Program.cs            # wiring de DI
  Worker.cs             # orquestrador
  Core/                 # NetworkEvent, buffers, consumer
  Infrastructure/
    Kernel/             # ETW process monitor
    Network/            # SharpPcap sniffer
    Security/           # mTLS, verifier, executor, replay cache
  Infrastructure/Grpc/  # proto gerado
  Protos/               # edr_telemetry.proto
  scripts/             # DevPki.cs (file-based), New-DevPki.ps1
  tests/               # xUnit
```

## 📝 Notas

- O agente não deve consumir mais de 50MB de RAM.
- Falhas de captura não derrubam o serviço; são logadas e a escuta continua.
- `certs/`, `bin/`, `obj/` e `.vs/` são gitignored.