using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EdrAgentMonitor.Infrastructure.Security
{
    // Carrega certificados de arquivo (dev) ou do Windows Certificate Store (produção)
    public static class CertificateLoader
    {
        public static X509Certificate2 Load(CertificateSourceOptions options, bool requirePrivateKey, string baseDirectory)
        {
            var cert = options.Source switch
            {
                CertificateSource.File => LoadFromFile(options, baseDirectory),
                CertificateSource.Store => LoadFromStore(options),
                _ => throw new InvalidOperationException($"Fonte de certificado inválida: {options.Source}")
            };

            if (requirePrivateKey && !cert.HasPrivateKey)
            {
                cert.Dispose();
                throw new InvalidOperationException("O certificado do agente não possui chave privada.");
            }

            return cert;
        }

        // Aceita PEM "PUBLIC KEY" (SPKI) ou um certificado (PEM/DER) contendo a chave pública
        public static ECDsa LoadSigningPublicKey(string path, string baseDirectory)
        {
            var fullPath = System.IO.Path.GetFullPath(path, baseDirectory);
            var text = File.ReadAllText(fullPath);

            ECDsa key;
            if (text.Contains("BEGIN PUBLIC KEY", StringComparison.Ordinal))
            {
                key = ECDsa.Create();
                key.ImportFromPem(text);
            }
            else
            {
                using var cert = X509CertificateLoader.LoadCertificateFromFile(fullPath);
                key = cert.GetECDsaPublicKey()
                    ?? throw new InvalidOperationException($"'{path}' não contém chave ECDSA.");
            }

            // Fixa o algoritmo: apenas P-256 é aceito
            if (key.KeySize != 256)
            {
                key.Dispose();
                throw new InvalidOperationException($"'{path}': esperado ECDSA P-256.");
            }

            return key;
        }

        private static X509Certificate2 LoadFromFile(CertificateSourceOptions o, string baseDirectory)
        {
            if (string.IsNullOrWhiteSpace(o.Path))
                throw new InvalidOperationException("Path do certificado não configurado.");

            var fullPath = System.IO.Path.GetFullPath(o.Path, baseDirectory);
            var ext = System.IO.Path.GetExtension(fullPath);

            return ext.Equals(".pfx", StringComparison.OrdinalIgnoreCase) || ext.Equals(".p12", StringComparison.OrdinalIgnoreCase)
                ? X509CertificateLoader.LoadPkcs12FromFile(fullPath, o.Password)
                : X509CertificateLoader.LoadCertificateFromFile(fullPath);
        }

        private static X509Certificate2 LoadFromStore(CertificateSourceOptions o)
        {
            if (string.IsNullOrWhiteSpace(o.Thumbprint))
                throw new InvalidOperationException("Thumbprint do certificado não configurado.");

            using var store = new X509Store(o.StoreName, o.StoreLocation);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            var thumb = o.Thumbprint.Replace(" ", "", StringComparison.Ordinal);
            var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumb, validOnly: false);

            return found.Count == 1
                ? found[0]
                : throw new InvalidOperationException(
                    $"Certificado {thumb} não encontrado em {o.StoreLocation}\\{o.StoreName}.");
        }
    }
}
