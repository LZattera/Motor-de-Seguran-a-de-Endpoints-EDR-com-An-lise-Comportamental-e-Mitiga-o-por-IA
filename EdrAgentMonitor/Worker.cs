using EdrAgentMonitor.Infrastructure.Network;
using KernelMonitor = EdrAgentMonitor.Infrastructure.Kernel.EdrAgentMonitor;

namespace EdrAgentMonitor
{
    public class Worker(ILogger<Worker> logger, NetworkSniffer sniffer) : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            logger.LogInformation("Serviço EDR iniciado em: {time}", DateTimeOffset.Now);

            // Produtor de rede: captura em thread própria do SharpPcap
            try
            {
                sniffer.Start();
            }
            catch (Exception ex)
            {
                // Regra 4: sem Npcap/permissão, o resto do agente continua
                logger.LogError(ex, "Falha ao iniciar o sniffer de rede.");
            }
            using var snifferRegistration = stoppingToken.Register(sniffer.Stop);

            // Instancia o nosso monitor
            var monitor = new KernelMonitor();

            // Encerra a sessão ETW quando o serviço for parado
            using var registration = stoppingToken.Register(monitor.Stop);

            // Roda o monitor em uma thread dedicada (Source.Process() é bloqueante)
            var monitorTask = Task.Factory.StartNew(() =>
            {
                try
                {
                    monitor.StartMonitoring();
                }
                catch (Exception ex)
                {
                    // Regra 4: nunca derrubar o serviço por falha na captura
                    logger.LogError(ex, "Falha no monitor de Kernel.");
                }
            }, stoppingToken, TaskCreationOptions.LongRunning, TaskScheduler.Default);

            // Mantém o Worker vivo
            try
            {
                await Task.Delay(Timeout.Infinite, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                // Encerramento normal
            }

            await monitorTask;
        }
    }
}
