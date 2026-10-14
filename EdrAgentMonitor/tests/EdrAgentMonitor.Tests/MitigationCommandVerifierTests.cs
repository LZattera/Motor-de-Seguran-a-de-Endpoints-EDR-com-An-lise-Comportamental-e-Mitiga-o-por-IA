using System.Security.Cryptography;
using EdrAgentMonitor.Infrastructure.Grpc;
using EdrAgentMonitor.Infrastructure.Security;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace EdrAgentMonitor.Tests;

public sealed class MitigationCommandVerifierTests : IDisposable
{
    private const string AgentId = "AGENT-01";
    private const string KeyId = "dev";
    private static readonly DateTimeOffset Now = new(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);

    private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly MitigationCommandVerifier _verifier;

    public MitigationCommandVerifierTests()
    {
        var publicOnly = ECDsa.Create();
        publicOnly.ImportSubjectPublicKeyInfo(_signingKey.ExportSubjectPublicKeyInfo(), out _);

        _verifier = new MitigationCommandVerifier(
            new Dictionary<string, ECDsa> { [KeyId] = publicOnly },
            AgentId,
            clockSkew: TimeSpan.FromSeconds(60),
            maxLifetime: TimeSpan.FromMinutes(5),
            new ReplayCache(),
            new FixedTimeProvider(Now));
    }

    [Fact]
    public void ValidCommand_IsAccepted()
    {
        var result = _verifier.Verify(Sign(NewPayload()));

        var ok = Assert.IsType<VerificationResult.Verified>(result);
        Assert.Equal("Stop-Process -Id 1234 -Force", ok.Payload.PowershellScript);
    }

    [Fact]
    public void TamperedPayload_IsRejected()
    {
        var cmd = Sign(NewPayload());
        var bytes = cmd.Payload.ToByteArray();
        bytes[^1] ^= 0x01;
        cmd.Payload = ByteString.CopyFrom(bytes);

        AssertRejected(cmd, "assinatura inválida");
    }

    [Fact]
    public void SignedByUnknownKey_IsRejected() =>
        AssertRejected(Sign(NewPayload(), _attackerKey), "assinatura inválida");

    [Fact]
    public void UnknownKeyId_IsRejected() =>
        AssertRejected(Sign(NewPayload(), keyId: "rogue"), "key_id desconhecido");

    [Fact]
    public void MissingSignature_IsRejected()
    {
        var cmd = Sign(NewPayload());
        cmd.Signature = ByteString.Empty;
        AssertRejected(cmd, "payload ou assinatura ausente");
    }

    [Fact]
    public void CommandForAnotherAgent_IsRejected() =>
        AssertRejected(Sign(NewPayload(agent: "AGENT-02")), "comando destinado a outro agente");

    [Fact]
    public void ExpiredCommand_IsRejected() =>
        AssertRejected(Sign(NewPayload(issued: Now.AddMinutes(-10), expires: Now.AddMinutes(-6))), "comando expirado");

    [Fact]
    public void CommandIssuedInFuture_IsRejected() =>
        AssertRejected(Sign(NewPayload(issued: Now.AddMinutes(10), expires: Now.AddMinutes(12))), "emitido no futuro");

    [Fact]
    public void LifetimeAboveLimit_IsRejected() =>
        AssertRejected(Sign(NewPayload(expires: Now.AddHours(1))), "janela de validade inválida");

    [Fact]
    public void ReplayedCommand_IsRejected()
    {
        var cmd = Sign(NewPayload());

        Assert.IsType<VerificationResult.Verified>(_verifier.Verify(cmd));
        AssertRejected(cmd, "replay detectado (command_id repetido)");
    }

    [Fact]
    public void GarbageWithValidSignature_IsRejectedAsMalformed()
    {
        var garbage = new byte[] { 0xFF, 0xFF, 0xFF };
        var cmd = new MitigationCommand
        {
            Payload = ByteString.CopyFrom(garbage),
            Signature = ByteString.CopyFrom(_signingKey.SignData(garbage, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)),
            KeyId = KeyId
        };

        AssertRejected(cmd, "payload malformado");
    }

    private void AssertRejected(MitigationCommand cmd, string expectedReason)
    {
        var rejected = Assert.IsType<VerificationResult.Rejected>(_verifier.Verify(cmd));
        Assert.Equal(expectedReason, rejected.Reason);
    }

    private static MitigationPayload NewPayload(string agent = AgentId, DateTimeOffset? issued = null, DateTimeOffset? expires = null) => new()
    {
        CommandId = Guid.NewGuid().ToString(),
        TargetAgentId = agent,
        PowershellScript = "Stop-Process -Id 1234 -Force",
        Reason = "teste",
        TargetProcessId = 1234,
        IssuedAt = Timestamp.FromDateTimeOffset(issued ?? Now),
        ExpiresAt = Timestamp.FromDateTimeOffset(expires ?? Now.AddMinutes(2))
    };

    private MitigationCommand Sign(MitigationPayload payload, ECDsa? key = null, string keyId = KeyId)
    {
        var bytes = payload.ToByteArray();
        var signature = (key ?? _signingKey).SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return new MitigationCommand
        {
            Payload = ByteString.CopyFrom(bytes),
            Signature = ByteString.CopyFrom(signature),
            KeyId = keyId
        };
    }

    public void Dispose()
    {
        _signingKey.Dispose();
        _attackerKey.Dispose();
    }
}

internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}
