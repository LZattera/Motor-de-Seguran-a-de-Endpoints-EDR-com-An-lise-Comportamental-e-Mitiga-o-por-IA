using System.Net.NetworkInformation;
using System.Net.Sockets;
using EdrAgentMonitor.Core;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace EdrAgentMonitor.Infrastructure.Network
{
    // Produtor: captura pacotes em modo promíscuo e publica no buffer de telemetria.
    // Não faz I/O na thread de captura — apenas parse mínimo + TryWrite O(1).
    public sealed class NetworkSniffer : IDisposable
    {
        // Porta ignorada (canal de comunicação do próprio agente)
        private const int IgnoredPort = 5001;
        private const int ReadTimeoutMs = 1000;

        private readonly ILogger<NetworkSniffer> _logger;
        private readonly TelemetryBufferService _buffer;
        private LibPcapLiveDevice? _device;
        private long _parseErrors;

        public NetworkSniffer(ILogger<NetworkSniffer> logger, TelemetryBufferService buffer)
        {
            _logger = logger;
            _buffer = buffer;
        }

        public void Start()
        {
            _device = SelectPrimaryDevice()
                ?? throw new InvalidOperationException("Nenhuma interface de rede ativa encontrada.");

            _device.OnPacketArrival += OnPacketArrival;
            _device.Open(new DeviceConfiguration
            {
                Mode = DeviceModes.Promiscuous,
                ReadTimeout = ReadTimeoutMs
            });

            // Filtro BPF aplicado no driver: descarta a porta 5001 antes de chegar ao C#
            _device.Filter = $"ip and not port {IgnoredPort}";

            _logger.LogInformation("Sniffer iniciado na interface: {Interface}", _device.Description);

            // Captura em thread interna do SharpPcap (não bloqueia o chamador)
            _device.StartCapture();
        }

        public void Stop()
        {
            if (_device is null) return;

            try
            {
                if (_device.Started) _device.StopCapture();
                _device.OnPacketArrival -= OnPacketArrival;
                _device.Close();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Erro ao encerrar o sniffer.");
            }
        }

        private void OnPacketArrival(object sender, PacketCapture e)
        {
            // Regra 4: falha num pacote nunca interrompe a escuta
            try
            {
                var raw = e.GetPacket();
                var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

                var ip = packet.Extract<IPPacket>();
                if (ip is null) return;

                ushort srcPort = 0, dstPort = 0;
                if (ip.PayloadPacket is TcpPacket tcp)
                {
                    srcPort = tcp.SourcePort;
                    dstPort = tcp.DestinationPort;
                }
                else if (ip.PayloadPacket is UdpPacket udp)
                {
                    srcPort = udp.SourcePort;
                    dstPort = udp.DestinationPort;
                }

                // Não bloqueante: em DropOldest o canal descarta o mais antigo se cheio
                _buffer.TryPublish(new NetworkEvent(
                    ip.SourceAddress, ip.DestinationAddress, srcPort, dstPort, raw.Timeval.Date));
            }
            catch (Exception ex)
            {
                // Regra 4 + anti-flood de log: registra só o 1º erro e depois a cada 10.000
                var n = Interlocked.Increment(ref _parseErrors);
                if (n == 1 || n % 10_000 == 0)
                    _logger.LogError(ex, "Falha ao processar pacote (total de falhas: {Count}).", n);
            }
        }

        // Interface principal = a que possui o gateway padrão IPv4 ativo
        private static LibPcapLiveDevice? SelectPrimaryDevice()
        {
            var primaryNic = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                         && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .FirstOrDefault(n => n.GetIPProperties().GatewayAddresses
                    .Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork
                           && !g.Address.Equals(System.Net.IPAddress.Any)));

            var devices = LibPcapLiveDeviceList.Instance;

            if (primaryNic is not null)
            {
                // No Windows o nome do dispositivo Npcap contém o GUID da NIC
                var match = devices.FirstOrDefault(d =>
                    d.Name.Contains(primaryNic.Id, StringComparison.OrdinalIgnoreCase));
                if (match is not null) return match;
            }

            // Fallback: primeira interface não-loopback com endereço IPv4
            return devices.FirstOrDefault(d =>
                !d.Loopback &&
                d.Addresses.Any(a => a.Addr?.ipAddress?.AddressFamily == AddressFamily.InterNetwork));
        }

        public void Dispose() => Stop();
    }
}
