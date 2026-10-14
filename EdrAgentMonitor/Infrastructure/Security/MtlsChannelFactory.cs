using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Grpc.Net.Client;
using Microsoft.Extensions.Options;

namespace EdrAgentMonitor.Infrastructure.Security
{
    // Cria o canal gRPC com TLS mútuo e pinning da CA privada do EDR
    public sealed class MtlsChannelFactory(IOptions<SecurityOptions> options, IHostEnvironment env)
    {
        private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

        // Lança exceção se a configuração estiver ausente/inválida (fail-closed): sem mTLS, sem canal.
        public GrpcChannel Create()
        {
            var o = options.Value;
            var clientCert = CertificateLoader.Load(o.ClientCertificate, requirePrivateKey: true, env.ContentRootPath);
            var trustedCa = CertificateLoader.Load(o.TrustedCa, requirePrivateKey: false, env.ContentRootPath);

            var handler = new SocketsHttpHandler
            {
                SslOptions = new SslClientAuthenticationOptions
                {
                    ClientCertificates = new X509CertificateCollection { clientCert },
                    EnabledSslProtocols = SslProtocols.Tls13,
                    RemoteCertificateValidationCallback = (_, cert, _, errors) =>
                        ValidateServerCertificate(cert, errors, trustedCa)
                },
                KeepAlivePingDelay = TimeSpan.FromSeconds(30),
                KeepAlivePingTimeout = TimeSpan.FromSeconds(10),
                EnableMultipleHttp2Connections = true
            };

            return GrpcChannel.ForAddress(o.ServerEndpoint, new GrpcChannelOptions { HttpHandler = handler });
        }

        // Aceita o servidor somente se o certificado encadear até a NOSSA CA (nem as CAs públicas do Windows valem)
        public static bool ValidateServerCertificate(X509Certificate? certificate, SslPolicyErrors errors, X509Certificate2 trustedCa)
        {
            if (certificate is null) return false;

            // Hostname divergente ou ausência de cert são falhas definitivas.
            // Erros de cadeia são esperados (CA privada não está no store) e reavaliados abaixo.
            if ((errors & (SslPolicyErrors.RemoteCertificateNotAvailable | SslPolicyErrors.RemoteCertificateNameMismatch)) != 0)
                return false;

            var serverCert = certificate as X509Certificate2
                ?? X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(trustedCa);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // CA privada sem CRL publicada
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthOid));

            if (!chain.Build(serverCert)) return false;

            // Pinning: o root da cadeia precisa ser exatamente a CA configurada
            var root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
            return root.RawDataMemory.Span.SequenceEqual(trustedCa.RawDataMemory.Span);
        }
    }
}
