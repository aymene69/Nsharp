using Nsharp.Components;
using Nsharp.Services;

var builder = WebApplication.CreateBuilder(args);

// Configurer les logs
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Debug);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Enregistrer HttpClient pour le service d'IA
builder.Services.AddHttpClient<AiAnalysisService>();

// Enregistrer les services personnalisés
try 
{
    builder.Services.AddSingleton<SettingsService>();
    builder.Services.AddSingleton<PortServiceLookup>(); // Chargement de la DB nmap
    builder.Services.AddSingleton<NetworkScanner>();
    builder.Services.AddSingleton<PdfReportService>();
    builder.Services.AddSingleton<HistoryService>(); // Service d'historique des scans

}
catch (Exception ex)
{
    Console.WriteLine($"FATAL ERROR during service registration: {ex}");
    throw;
}

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
