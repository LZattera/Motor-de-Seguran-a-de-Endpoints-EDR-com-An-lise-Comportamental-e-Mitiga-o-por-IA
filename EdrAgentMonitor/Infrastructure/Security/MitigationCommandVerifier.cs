using System.Security.Cryptography;
using EdrAgentMonitor.Infrastructure.Grpc;
using Google.Protobuf;

namespace EdrAgentMonitor.Infrastructure.Security
{
    public abstract record VerificationResult
    {
        public sealed record Verified(MitigationPayload Payload) : VerificationResult;
        public sealed record Rejected(string Reason) : VerificationResult;
    }

    // Valida um MitigationCommand antes de qualquer execução. Qualquer falha = rejeição.
    public sealed class MitigationCommandVerifier
    {
        private readonly IReadOnlyDictionary<string, ECDsa> _keys;
        private readonly string _agentId;
        private readonly TimeSpan _clockSkew;
        private readonly TimeSpan _maxLifetime;
        private readonly ReplayCache _replayCache;
        private readonly TimeProvider _time;

        public MitigationCommandVerifier(
            IReadOnlyDictionary<string, ECDsa> trustedKeys,
            string agentId,
            TimeSpan clockSkew,
            TimeSpan maxLifetime,
            ReplayCache replayCache,
            TimeProvider time)
        {
            _keys = trustedKeys;
            _agentId = agentId;
            _clockSkew = clockSkew;
            _maxLifetime = maxLifetime;
            _replayCache = replayCache;
            _time = time;
        }

        // Chaves inválidas/ausentes são ignoradas e logadas: sem chave confiável, tudo é rejeitado (fail-closed)
        public static MitigationCommandVerifier FromOptions(
            SecurityOptions o, string baseDirectory, ReplayCache cache, TimeProvider time, ILogger logger)
        {
            var keys = new Dictionary<string, ECDsa>(StringComparer.Ordinal);
            foreach (var (keyId, path) in o.SigningPublicKeys)
            {
                try
                {
                    keys[keyId] = CertificateLoader.LoadSigningPublicKey(path, baseDirectory);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Chave de assinatura '{KeyId}' inválida ({Path}).", keyId, path);
                }
            }

            if (keys.Count == 0)
                logger.LogWarning("Nenhuma chave de assinatura confiável: TODOS os comandos de mitigação serão rejeitados.");

            return new MitigationCommandVerifier(
                keys, o.ResolveAgentId(),
                TimeSpan.FromSeconds(o.ClockSkewSeconds),
                TimeSpan.FromSeconds(o.MaxCommandLifetimeSeconds),
                cache, time);
        }

        public VerificationResult Verify(MitigationCommand command)
        {
            if (command.Payload.IsEmpty || command.Signature.IsEmpty)
                return Reject("payload ou assinatura ausente");

            if (!_keys.TryGetValue(command.KeyId, out var key))
                return Reject("key_id desconhecido");

            // 1) Criptografia primeiro: nenhum byte não autenticado é interpretado
            if (!key.VerifyData(command.Payload.Span, command.Signature.Span,
                    HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
                return Reject("assinatura inválida");

            MitigationPayload payload;
            try
            {
                payload = MitigationPayload.Parser.ParseFrom(command.Payload);
            }
            catch (InvalidProtocolBufferException)
            {
                return Reject("payload malformado");
            }

            // 2) Destino
            if (!string.Equals(payload.TargetAgentId, _agentId, StringComparison.Ordinal))
                return Reject("comando destinado a outro agente");

            // 3) Janela de validade
            if (payload.IssuedAt is null || payload.ExpiresAt is null)
                return Reject("issued_at/expires_at ausente");

            var now = _time.GetUtcNow();
            var issued = payload.IssuedAt.ToDateTimeOffset();
            var expires = payload.ExpiresAt.ToDateTimeOffset();

            if (issued > now + _clockSkew) return Reject("emitido no futuro");
            if (expires <= now - _clockSkew) return Reject("comando expirado");
            if (expires <= issued || expires - issued > _maxLifetime) return Reject("janela de validade inválida");

            if (string.IsNullOrWhiteSpace(payload.CommandId)) return Reject("command_id ausente");
            if (string.IsNullOrWhiteSpace(payload.PowershellScript)) return Reject("script vazio");

            // 4) Anti-replay (por último: só registra comandos que passaram em todo o resto)
            if (!_replayCache.TryRegister(payload.CommandId, expires + _clockSkew, now))
                return Reject("replay detectado (command_id repetido)");

            return new VerificationResult.Verified(payload);
        }

        private static VerificationResult.Rejected Reject(string reason) => new(reason);
    }
}
