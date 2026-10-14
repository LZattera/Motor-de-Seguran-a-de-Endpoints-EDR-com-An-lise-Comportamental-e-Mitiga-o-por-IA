using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EdrAgentMonitor.Infrastructure.Security;

namespace EdrAgentMonitor.Tests;

public sealed class MtlsServerValidationTests : IDisposable
{
    private readonly X509Certificate2 _trustedCa;
    private readonly ECDsa _trustedCaKey;
    private readonly X509Certificate2 _rogueCa;
    private readonly ECDsa _rogueCaKey;

    public MtlsServerValidationTests()
    {
        (_trustedCa, _trustedCaKey) = CreateCa("CN=Trusted CA");
        (_rogueCa, _rogueCaKey) = CreateCa("CN=Rogue CA");
    }

    [Fact]
    public void ServerCertFromPinnedCa_IsAccepted()
    {
        using var server = CreateServerCert(_trustedCa);
        Assert.True(MtlsChannelFactory.ValidateServerCertificate(server, SslPolicyErrors.RemoteCertificateChainErrors, _trustedCa));
    }

    [Fact]
    public void ServerCertFromUnknownCa_IsRejected()
    {
        using var server = CreateServerCert(_rogueCa);
        Assert.False(MtlsChannelFactory.ValidateServerCertificate(server, SslPolicyErrors.RemoteCertificateChainErrors, _trustedCa));
    }

    [Fact]
    public void HostnameMismatch_IsRejectedEvenWithPinnedCa()
    {
        using var server = CreateServerCert(_trustedCa);
        Assert.False(MtlsChannelFactory.ValidateServerCertificate(server, SslPolicyErrors.RemoteCertificateNameMismatch, _trustedCa));
    }

    [Fact]
    public void ClientAuthOnlyCert_IsRejectedAsServer()
    {
        using var clientCert = CreateServerCert(_trustedCa, ekuOid: "1.3.6.1.5.5.7.3.2");
        Assert.False(MtlsChannelFactory.ValidateServerCertificate(clientCert, SslPolicyErrors.None, _trustedCa));
    }

    [Fact]
    public void MissingCertificate_IsRejected() =>
        Assert.False(MtlsChannelFactory.ValidateServerCertificate(null, SslPolicyErrors.RemoteCertificateNotAvailable, _trustedCa));

    private static (X509Certificate2, ECDsa) CreateCa(string subject)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        var now = DateTimeOffset.UtcNow;
        return (req.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(2)), key);
    }

    private static X509Certificate2 CreateServerCert(X509Certificate2 issuer, string ekuOid = "1.3.6.1.5.5.7.3.1")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ekuOid) }, false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        req.CertificateExtensions.Add(san.Build());

        var now = DateTimeOffset.UtcNow;
        return req.Create(issuer, now.AddMinutes(-1), now.AddDays(1), RandomNumberGenerator.GetBytes(8));
    }

    public void Dispose()
    {
        _trustedCa.Dispose(); _trustedCaKey.Dispose();
        _rogueCa.Dispose(); _rogueCaKey.Dispose();
    }
}
