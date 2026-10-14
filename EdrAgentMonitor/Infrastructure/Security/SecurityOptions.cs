namespace EdrAgentMonitor.Infrastructure.Security
{
    // Seção "Security" do appsettings.json. Segredos (senha do PFX) via user-secrets / variáveis de ambiente.
    public sealed class SecurityOptions
    {
        public const string SectionName = "Security";

        // Vazio = nome da máquina
        public string AgentId { get; set; } = "";
        public string ServerEndpoint { get; set; } = "https://localhost:5001";

        // Certificado do agente (com chave privada) apresentado no mTLS
        public CertificateSourceOptions ClientCertificate { get; set; } = new();

        // CA privada do EDR: único root aceito para o certificado do servidor (pinning)
        public CertificateSourceOptions TrustedCa { get; set; } = new();

        // key_id -> arquivo com a chave pública de assinatura (PEM "PUBLIC KEY" ou certificado)
        public Dictionary<string, string> SigningPublicKeys { get; set; } = new();

        public int ClockSkewSeconds { get; set; } = 60;
        public int MaxCommandLifetimeSeconds { get; set; } = 300;

        public ExecutorOptions Executor { get; set; } = new();

        public string ResolveAgentId() =>
            string.IsNullOrWhiteSpace(AgentId) ? Environment.MachineName : AgentId;
    }

    public enum CertificateSource { File, Store }

    public sealed class CertificateSourceOptions
    {
        public CertificateSource Source { get; set; } = CertificateSource.File;

        // Source = File
        public string? Path { get; set; }
        public string? Password { get; set; }

        // Source = Store
        public string? Thumbprint { get; set; }
        public System.Security.Cryptography.X509Certificates.StoreLocation StoreLocation { get; set; }
            = System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine;
        public System.Security.Cryptography.X509Certificates.StoreName StoreName { get; set; }
            = System.Security.Cryptography.X509Certificates.StoreName.My;
    }

    public enum ExecutionMode
    {
        DryRun,   // Padrão: apenas registra o script que seria executado
        Enforce   // Executa de fato (opt-in explícito)
    }

    public sealed class ExecutorOptions
    {
        public ExecutionMode Mode { get; set; } = ExecutionMode.DryRun;
        public int TimeoutSeconds { get; set; } = 60;
    }
}
