using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace EdrAgentMonitor.Infrastructure.Kernel
{
    // Fundação do Agente C# para captura de eventos do Kernel
    public class EdrAgentMonitor
    {
        private TraceEventSession? _session;

        public void StartMonitoring()
        {
            // Cria uma sessão de rastreamento no nível do SO
            using (var session = new TraceEventSession("MeuEdrSession"))
            {
                _session = session;

                // Habilita a escuta de eventos de processos do Kernel
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

                // Callback disparado milissegundos após um processo tentar iniciar
                session.Source.Kernel.ProcessStart += data =>
                {
                    Console.WriteLine($"[ALERTA] Processo Iniciado: {data.ProcessName} (PID: {data.ProcessID})");
                    Console.WriteLine($"Caminho: {data.ImageFileName}");
                    Console.WriteLine($"Linha de Comando: {data.CommandLine}");

                    // Aqui entra a lógica de segurança:
                    // Se o caminho for suspeito ou não assinado, disparamos a mitigação.
                    AnalyzeProcessSecurity(data.ProcessID, data.ImageFileName);
                };

                // Inicia o bloqueio da thread para escutar os eventos
                session.Source.Process();
                _session = null;
            }
        }

        // Interrompe a sessão ETW, liberando a thread bloqueada em Source.Process()
        public void Stop() => _session?.Stop();

        private void AnalyzeProcessSecurity(int pid, string fileName)
        {
            // Apenas um log temporário para testes
            Console.WriteLine($"[ANALISANDO] PID: {pid} | Arquivo: {fileName}");
        }
    }
}
