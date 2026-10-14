using System.Threading.Channels;

namespace EdrAgentMonitor.Core
{
    // Buffer central de telemetria: desacopla produtores (sniffer) de consumidores (envio de logs)
    public sealed class TelemetryBufferService
    {
        public const int Capacity = 100_000;

        private readonly Channel<NetworkEvent> _channel;
        private long _dropped;

        public TelemetryBufferService()
        {
            _channel = Channel.CreateBounded<NetworkEvent>(
                new BoundedChannelOptions(Capacity)
                {
                    // Regra 3: sob sobrecarga descarta o mais antigo, nunca bloqueia o produtor
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleReader = true,
                    SingleWriter = false,
                    AllowSynchronousContinuations = false
                },
                _ => Interlocked.Increment(ref _dropped));
        }

        public ChannelReader<NetworkEvent> Reader => _channel.Reader;

        // Total de eventos descartados por overflow desde o início
        public long DroppedCount => Interlocked.Read(ref _dropped);

        public int Count => _channel.Reader.Count;

        // Escrita O(1) sem lock pesado e sem bloqueio: em DropOldest sempre retorna true
        public bool TryPublish(in NetworkEvent evt) => _channel.Writer.TryWrite(evt);

        public void Complete() => _channel.Writer.TryComplete();
    }
}
