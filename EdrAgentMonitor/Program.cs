using EdrAgentMonitor;
using EdrAgentMonitor.Core;
using EdrAgentMonitor.Infrastructure.Network;
using EdrAgentMonitor.Infrastructure.Security;
using Microsoft.Extensions.Options;

var builder = Host.CreateApplicationBuilder(args);

// Pipeline de telemetria: Produtor (NetworkSniffer) -> Channel -> Consumidor
builder.Services.AddSingleton<TelemetryBufferService>();
builder.Services.AddSingleton<NetworkSniffer>();
builder.Services.AddHostedService<TelemetryConsumerService>();

// Segurança do canal de mitigação (mTLS + comandos assinados).
// Fail-closed sem derrubar o agente: config inválida => canal não abre / comandos rejeitados.
builder.Services.Configure<SecurityOptions>(builder.Configuration.GetSection(SecurityOptions.SectionName));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<ReplayCache>(_ => new ReplayCache());
builder.Services.AddSingleton(sp => MitigationCommandVerifier.FromOptions(
    sp.GetRequiredService<IOptions<SecurityOptions>>().Value,
    sp.GetRequiredService<IHostEnvironment>().ContentRootPath,
    sp.GetRequiredService<ReplayCache>(),
    sp.GetRequiredService<TimeProvider>(),
    sp.GetRequiredService<ILoggerFactory>().CreateLogger<MitigationCommandVerifier>()));
builder.Services.AddSingleton<MitigationExecutor>();
builder.Services.AddSingleton<MitigationCommandHandler>();
builder.Services.AddSingleton<MtlsChannelFactory>();

builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
