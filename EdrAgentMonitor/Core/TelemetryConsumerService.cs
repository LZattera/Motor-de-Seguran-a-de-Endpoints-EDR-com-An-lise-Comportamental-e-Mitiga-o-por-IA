namespace EdrAgentMonitor.Core
{
    // Consumidor básico: drena o canal em lotes de até 500 eventos a cada 100ms
    public sealed class TelemetryConsumerService(
        TelemetryBufferService buffer,
        ILogger<TelemetryConsumerService> logger) : BackgroundService
    {
        private const int BatchSize = 500;
        private static readonly TimeSpan Interval = TimeSpan.FromMilliseconds(100);

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Lote reutilizado: zero alocação por ciclo
            var batch = new List<NetworkEvent>(BatchSize);
            using var timer = new PeriodicTimer(Interval);
            long lastDropped = 0;

            try
            {
                while (await timer.WaitForNextTickAsync(stoppingToken))
                {
                    batch.Clear();
                    while (batch.Count < BatchSize && buffer.Reader.TryRead(out var evt))
                        batch.Add(evt);

                    if (batch.Count == 0) continue;

                    try
                    {
                        ProcessBatch(batch, ref lastDropped);
                    }
                    catch (Exception ex)
                    {
                        // Regra 4: falha no lote não derruba o consumidor
                        logger.LogError(ex, "Falha ao processar lote de telemetria.");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Encerramento normal
            }
        }

        private void ProcessBatch(List<NetworkEvent> batch, ref long lastDropped)
        {
            // Placeholder até o envio gRPC: resumo por lote em vez de 1 linha/pacote
            // (Console por pacote é justamente o gargalo que queremos evitar)
            var first = batch[0];
            Console.WriteLine(
                $"[LOTE] {batch.Count} eventos | pendentes: {buffer.Count} | " +
                $"ex: {first.SourceIp}:{first.SourcePort} -> {first.DestinationIp}:{first.DestinationPort}");

            var dropped = buffer.DroppedCount;
            if (dropped != lastDropped)
            {
                logger.LogWarning("Buffer cheio: {Count} eventos descartados (total).", dropped);
                lastDropped = dropped;
            }
        }
    }
}
