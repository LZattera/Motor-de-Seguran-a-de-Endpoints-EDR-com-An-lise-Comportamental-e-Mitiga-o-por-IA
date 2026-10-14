namespace EdrAgentMonitor.Infrastructure.Security
{
    // Memória de command_ids já aceitos. Cada id só precisa ser lembrado até expirar:
    // depois disso a checagem de validade já rejeita o comando.
    public sealed class ReplayCache(int capacity = ReplayCache.DefaultCapacity)
    {
        public const int DefaultCapacity = 10_000; // ~1MB no pior caso: respeita o teto de 50MB

        private readonly Dictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
        private readonly Lock _lock = new();

        // true = primeira vez (registrado); false = replay OU cache cheio (fail-closed)
        public bool TryRegister(string commandId, DateTimeOffset keepUntil, DateTimeOffset now)
        {
            lock (_lock)
            {
                if (_seen.TryGetValue(commandId, out var until) && until > now)
                    return false;

                if (_seen.Count >= capacity)
                {
                    PurgeExpired(now);
                    if (_seen.Count >= capacity) return false;
                }

                _seen[commandId] = keepUntil;
                return true;
            }
        }

        private void PurgeExpired(DateTimeOffset now)
        {
            foreach (var (id, until) in _seen)
                if (until <= now) _seen.Remove(id);
        }
    }
}
