// Gerador de PKI de DESENVOLVIMENTO para o EDR Agent.
// Uso (via wrapper):  .\scripts\New-DevPki.ps1
// Uso direto:         dotnet run scripts/DevPki.cs -- <outDir> <agentId> <serverDns> <validDays> <pfxPassword>
//
// Gera (tudo ECDSA P-256):
//   ca.crt               CA privada (pública)           -> agente e servidor confiam nela
//   server.pfx           cert TLS do servidor (serverAuth, SAN = serverDns)
//   agent.pfx            cert TLS do agente   (clientAuth, CN = agentId)
//   signing-private.pem  chave que ASSINA comandos     -> fica só no backend de IA
//   signing-public.pem   chave que VERIFICA comandos   -> vai para o agente
//
// A chave privada da CA NÃO é salva: para emitir novos certs, regere tudo.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

if (args.Length != 5)
{
    Console.Error.WriteLine("Uso: dotnet run DevPki.cs -- <outDir> <agentId> <serverDns> <validDays> <pfxPassword>");
    return 1;
}

var (outDir, agentId, serverDns, validDays, password) = (args[0], args[1], args[2], int.Parse(args[3]), args[4]);
Directory.CreateDirectory(outDir);

var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);

// ---- CA ----
using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var caReq = new CertificateRequest("CN=EDR Dev Root CA, O=EdrAgentMonitor", caKey, HashAlgorithmName.SHA256);
caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
caReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caReq.PublicKey, false));
using var ca = caReq.CreateSelfSigned(notBefore, notBefore.AddDays(validDays + 1));
File.WriteAllText(Path.Combine(outDir, "ca.crt"), ca.ExportCertificatePem());

// ---- Server / Agent ----
WriteLeaf("server.pfx", $"CN={serverDns}", "1.3.6.1.5.5.7.3.1", [serverDns]);
WriteLeaf("agent.pfx", $"CN={agentId}", "1.3.6.1.5.5.7.3.2", []);

// ---- Chaves de assinatura de comandos (independentes do TLS) ----
using (var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256))
{
    File.WriteAllText(Path.Combine(outDir, "signing-private.pem"), signing.ExportPkcs8PrivateKeyPem());
    File.WriteAllText(Path.Combine(outDir, "signing-public.pem"), signing.ExportSubjectPublicKeyInfoPem());
}

Console.WriteLine($"PKI de desenvolvimento gerada em: {Path.GetFullPath(outDir)}");
return 0;

void WriteLeaf(string file, string subject, string ekuOid, string[] dnsNames)
{
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
    req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
    req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ekuOid) }, false));
    req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
    req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, false));
    if (dnsNames.Length > 0)
    {
        var san = new SubjectAlternativeNameBuilder();
        foreach (var dns in dnsNames) san.AddDnsName(dns);
        req.CertificateExtensions.Add(san.Build());
    }

    var serial = RandomNumberGenerator.GetBytes(16);
    serial[0] &= 0x7F; // serial positivo

    using var cert = req.Create(ca, notBefore, notBefore.AddDays(validDays), serial);
    using var withKey = cert.CopyWithPrivateKey(key);
    File.WriteAllBytes(Path.Combine(outDir, file), withKey.Export(X509ContentType.Pkcs12, password));
}
