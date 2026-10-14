using EdrAgentMonitor.Infrastructure.Grpc;
using EdrAgentMonitor.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace EdrAgentMonitor.Tests;

public sealed class MitigationExecutorTests
{
    private static MitigationExecutor CreateExecutor(ExecutionMode mode) =>
        new(Options.Create(new SecurityOptions { Executor = new ExecutorOptions { Mode = mode, TimeoutSeconds = 30 } }),
            NullLogger<MitigationExecutor>.Instance);

    private static MitigationPayload Payload(string script) => new() { CommandId = "cmd-1", PowershellScript = script };

    [Fact]
    public async Task DryRun_DoesNotExecute()
    {
        var marker = Path.Combine(Path.GetTempPath(), $"edr-dryrun-{Guid.NewGuid():N}.txt");

        var result = await CreateExecutor(ExecutionMode.DryRun)
            .ExecuteAsync(Payload($"Set-Content -Path '{marker}' -Value x"), CancellationToken.None);

        Assert.Equal(ExecutionStatus.DryRun, result.Status);
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public async Task Enforce_ExecutesScriptWithSpecialCharacters()
    {
        // Aspas, ; e $ chegam intactos via -EncodedCommand (sem quebra/injeção de argumentos)
        var result = await CreateExecutor(ExecutionMode.Enforce)
            .ExecuteAsync(Payload("$a = 'x\"y'; Write-Output \"ok:$a\""), CancellationToken.None);

        Assert.Equal(ExecutionStatus.Succeeded, result.Status);
        Assert.Equal("ok:x\"y", result.Output);
    }

    [Fact]
    public async Task Enforce_NonZeroExit_IsReportedAsFailed()
    {
        var result = await CreateExecutor(ExecutionMode.Enforce)
            .ExecuteAsync(Payload("exit 3"), CancellationToken.None);

        Assert.Equal(ExecutionStatus.Failed, result.Status);
        Assert.Equal(3, result.ExitCode);
    }
}
