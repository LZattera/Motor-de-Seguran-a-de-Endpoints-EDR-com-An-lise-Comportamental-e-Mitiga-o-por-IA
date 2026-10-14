using System.Diagnostics;
using System.Text;
using EdrAgentMonitor.Infrastructure.Grpc;
using Microsoft.Extensions.Options;

namespace EdrAgentMonitor.Infrastructure.Security
{
    public enum ExecutionStatus { DryRun, Succeeded, Failed, TimedOut, Rejected }

    public sealed record ExecutionResult(string CommandId, ExecutionStatus Status, int? ExitCode = null, string Output = "", string Error = "");

    // Executa SOMENTE payloads já verificados pelo MitigationCommandVerifier
    public sealed class MitigationExecutor(IOptions<SecurityOptions> options, ILogger<MitigationExecutor> logger)
    {
        // Limite do Windows para a linha de comando (32.767) com folga para os demais argumentos
        private const int MaxEncodedLength = 32_000;
        private const int MaxCapturedChars = 8_192;

        // Caminho absoluto: evita sequestro via PATH
        private static readonly string PowerShellPath =
            Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");

        public async Task<ExecutionResult> ExecuteAsync(MitigationPayload payload, CancellationToken ct)
        {
            var o = options.Value.Executor;

            logger.LogWarning("[MITIGAÇÃO] Comando {CommandId} | PID alvo: {Pid} | Motivo: {Reason}",
                payload.CommandId, payload.TargetProcessId, payload.Reason);

            if (o.Mode == ExecutionMode.DryRun)
            {
                logger.LogWarning("[MITIGAÇÃO][DryRun] Script NÃO executado:{NewLine}{Script}",
                    Environment.NewLine, payload.PowershellScript);
                return new ExecutionResult(payload.CommandId, ExecutionStatus.DryRun);
            }

            // -EncodedCommand (Base64 UTF-16LE): o script nunca é concatenado na linha de comando -> sem injeção
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(payload.PowershellScript));
            if (encoded.Length > MaxEncodedLength)
            {
                logger.LogError("Script do comando {CommandId} excede o tamanho máximo.", payload.CommandId);
                return new ExecutionResult(payload.CommandId, ExecutionStatus.Rejected, Error: "script muito grande");
            }

            var psi = new ProcessStartInfo(PowerShellPath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            foreach (var arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive",
                                        "-ExecutionPolicy", "Restricted", // bloqueia carregar .ps1 externos
                                        "-EncodedCommand", encoded })
                psi.ArgumentList.Add(arg);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(o.TimeoutSeconds));

            try
            {
                using var process = Process.Start(psi)
                    ?? throw new InvalidOperationException("Falha ao iniciar o PowerShell.");

                var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
                var stderr = process.StandardError.ReadToEndAsync(timeout.Token);

                try
                {
                    await process.WaitForExitAsync(timeout.Token);
                }
                catch (OperationCanceledException)
                {
                    process.Kill(entireProcessTree: true);
                    logger.LogError("Comando {CommandId} excedeu o timeout e foi encerrado.", payload.CommandId);
                    return new ExecutionResult(payload.CommandId, ExecutionStatus.TimedOut);
                }

                var result = new ExecutionResult(
                    payload.CommandId,
                    process.ExitCode == 0 ? ExecutionStatus.Succeeded : ExecutionStatus.Failed,
                    process.ExitCode,
                    Truncate(await stdout),
                    Truncate(await stderr));

                logger.LogWarning("[MITIGAÇÃO] Comando {CommandId} finalizado: {Status} (exit {ExitCode})",
                    result.CommandId, result.Status, result.ExitCode);
                return result;
            }
            catch (Exception ex)
            {
                // Regra 4: falha na mitigação nunca derruba o agente
                logger.LogError(ex, "Falha ao executar comando {CommandId}.", payload.CommandId);
                return new ExecutionResult(payload.CommandId, ExecutionStatus.Failed, Error: ex.Message);
            }
        }

        private static string Truncate(string s) =>
            s.Length <= MaxCapturedChars ? s.TrimEnd() : s[..MaxCapturedChars] + "…[truncado]";
    }
}
