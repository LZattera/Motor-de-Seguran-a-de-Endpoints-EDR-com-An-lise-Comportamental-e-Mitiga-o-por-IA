# Sentinel EDR: Autonomous Endpoint Detection & Response

Um sistema de segurança cibernética (EDR) construído do zero, focado em detecção de ameaças em tempo real e resposta automatizada utilizando Inteligência Artificial local (Edge AI). 

Este projeto demonstra engenharia de software avançada, abrangendo manipulação de sistemas operativos a baixo nível, redes, mensageria de alta performance e orquestração de IA generativa em ambiente isolado (Air-Gapped).

## 🏗️ Arquitetura do Sistema

A arquitetura segue um modelo distribuído de Edge Computing, dividido em duas camadas principais:
1. **Endpoint (Agente Local):** Um *Daemon/Worker Service* em C# responsável pela interceptação de chamadas nativas do Kernel e captura de pacotes de rede.
2. **Control Plane (Servidor de Borda):** Um cluster conteinerizado responsável pela ingestão de telemetria, análise assíncrona de ameaças via orquestração de IA (n8n + Ollama) e despacho de ações de mitigação.

---

## ✅ O Que Já Foi Implementado (Fase 1)

### 1. Agente EDR (C# / .NET 8 Worker Service)
* **Monitorização de Kernel:** Interceptação em tempo real de eventos de criação de processos no sistema operativo utilizando `Microsoft.Diagnostics.Tracing.TraceEvent`.
* **Packet Sniffing:** Captura de tráfego de rede em modo promíscuo utilizando a biblioteca `SharpPcap`, com filtragem BPF nativa.
* **Otimização de Memória (Concorrência):** Implementação do padrão *Producer-Consumer* com `System.Threading.Channels`. A telemetria é retida em buffers circulares limitados (`BoundedChannel`), garantindo que o agente consuma recursos mínimos da CPU e não cause falhas de falta de memória (OOM).

### 2. Comunicação e Contratos
* **Streaming Bidirecional gRPC:** Definição do contrato `edr_telemetry.proto`. O agente envia lotes binários compactados de logs de rede e de processos de forma contínua, enquanto mantém a conexão aberta para receber comandos de defesa assíncronos.

### 3. Infraestrutura de Servidor (Docker Compose)
* **Redpanda:** Clone de alta performance do Apache Kafka, responsável pela absorção do tráfego massivo gRPC.
* **PostgreSQL + pgvector:** Armazenamento vetorial para retenção de eventos e suporte a RAG (Retrieval-Augmented Generation).
* **Ollama (Phi-3):** Motor de inferência de IA a correr localmente para geração de scripts de mitigação, eliminando custos com APIs externas e garantindo privacidade dos dados de segurança.
* **n8n:** Motor visual de automação de fluxos de trabalho que interliga o cluster de mensageria à IA.

---

## 🚀 Roadmap de Desenvolvimento (O Que Será Feito)

### Fase 2: Ingestão e Processamento
- [ ] **Gateway gRPC (.NET):** Desenvolver o servidor ASP.NET Core que recebe o streaming bidirecional do agente e atua como *Producer* de alta taxa de transferência para o cluster Redpanda/Kafka.
- [ ] **Worker de IA (.NET):** Criar o serviço de background que atua como *Consumer* do Redpanda, converte os logs em contexto JSON e aciona o *webhook* do orquestrador n8n.
- [ ] **Gerenciador de Conexões de Estado (Stateful):** Implementar o rastreamento em memória das sessões gRPC ativas para garantir que o script de mitigação retorne exatamente para a máquina atacada.

### Fase 3: Orquestração e Resposta Autônoma
- [ ] **Pipeline RAG no n8n:** Desenhar o fluxo visual que recebe a telemetria, injeta um *System Prompt* rigoroso de cibersegurança e extrai um script de defesa tática gerado pelo Ollama.
- [ ] **Motor de Execução (Agente):** Implementar a lógica no cliente C# para receber o comando de mitigação da nuvem (ex: PowerShell ou *iptables*) e executá-lo nativamente no sistema operativo para isolar a ameaça.

### Fase 4: Observabilidade e Interface (Opcional/Avançado)
- [ ] **Painel de Comando (Dashboard):** Implementar um frontend web reativo (SignalR/React) ou móvel (Flutter) para monitorização em tempo real das ações autônomas da IA.