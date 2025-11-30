using Nsharp.Components;
using Nsharp.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Enregistrer HttpClient pour le service d'IA
builder.Services.AddHttpClient<AiAnalysisService>();

// Enregistrer les services personnalisés
builder.Services.AddSingleton<SettingsService>();
builder.Services.AddSingleton<PortServiceLookup>(); // Chargement de la DB nmap
builder.Services.AddSingleton<NetworkScanner>();
builder.Services.AddSingleton<PdfReportService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
