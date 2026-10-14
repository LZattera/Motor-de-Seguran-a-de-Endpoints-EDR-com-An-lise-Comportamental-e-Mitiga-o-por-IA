using EdrAgentMonitor.Infrastructure.Grpc;

namespace EdrAgentMonitor.Infrastructure.Security
{
    // Ponto único de entrada para comandos vindos do servidor: verificar -> executar
    public sealed class MitigationCommandHandler(
        MitigationCommandVerifier verifier,
        MitigationExecutor executor,
        ILogger<MitigationCommandHandler> logger)
    {
        public async Task<ExecutionResult?> HandleAsync(MitigationCommand command, CancellationToken ct)
        {
            switch (verifier.Verify(command))
            {
                case VerificationResult.Verified ok:
                    return await executor.ExecuteAsync(ok.Payload, ct);

                case VerificationResult.Rejected rejected:
                    logger.LogWarning("[SEGURANÇA] Comando de mitigação REJEITADO: {Reason}", rejected.Reason);
                    return null;

                default:
                    return null;
            }
        }
    }
}
