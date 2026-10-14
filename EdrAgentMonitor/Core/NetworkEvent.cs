using System.Net;

namespace EdrAgentMonitor.Core
{
    // Evento de rede imutável e leve (struct evita pressão no GC sob alto tráfego)
    public readonly record struct NetworkEvent(
        IPAddress SourceIp,
        IPAddress DestinationIp,
        ushort SourcePort,
        ushort DestinationPort,
        DateTime TimestampUtc);
}
