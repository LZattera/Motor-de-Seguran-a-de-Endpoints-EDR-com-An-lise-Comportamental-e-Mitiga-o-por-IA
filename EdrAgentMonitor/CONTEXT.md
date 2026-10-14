# Contexto do Projeto: EDR Agent (Endpoint Detection and Response)

## Arquitetura Base
- **Stack:** C# (.NET 8.0), Worker Service.
- **Padrão de Projeto:** Clean Architecture simplificada.
- **Objetivo:** Monitorar processos (Kernel) e tráfego de rede localmente de forma ultra-performática, atuando como um Daemon/Serviço.

## Regras de Código (Strict Rules)
1. **Performance:** Utilize `System.Threading.Channels` para transferir dados entre produtores (coletores de eventos) e consumidores (envio de logs). Evite bloquear a thread principal (Thread Pool starvation).
2. **Bibliotecas Homologadas:** 
   - `Microsoft.Diagnostics.Tracing.TraceEvent` (para captura de processos no SO).
   - `SharpPcap` (para packet sniffing em modo promíscuo).
   - `Grpc.Net.Client` e `Google.Protobuf` (para comunicação).
3. **Resiliência:** O agente não pode consumir mais do que 50MB de RAM. Use `BoundedChannels` com `DropOldest` caso a ingestão de pacotes supere o envio.
4. **Tratamento de Exceções:** Nunca encerre o serviço principal por falhas na leitura de pacotes. Faça log da exceção e continue a escuta.