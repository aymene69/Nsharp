using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Nsharp.Models;

namespace Nsharp.Services;

public class AiAnalysisService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly SettingsService _settingsService;
    private readonly ILogger<AiAnalysisService> _logger;

    public AiAnalysisService(HttpClient httpClient, IConfiguration configuration, SettingsService settingsService, ILogger<AiAnalysisService> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _settingsService = settingsService;
        _logger = logger;
    }

    public async Task EnrichScanResultsAsync(List<ScanResult> results)
    {
        var settings = _settingsService.GetSettings();
        var apiKey = settings.AiApiKey;
        var apiUrl = _configuration["AiSettings:ApiUrl"] ?? "https://api.chatanywhere.tech/v1/chat/completions";
        var model = !string.IsNullOrEmpty(settings.AiModel) ? settings.AiModel : (_configuration["AiSettings:Model"] ?? "deepseek-chat");

        if (string.IsNullOrEmpty(apiKey))
        {
            _logger.LogWarning("AI ApiKey is missing in user settings. Skipping AI analysis.");
            return;
        }

        // Préparer les données pour l'IA (uniquement ce qui est nécessaire)
        var servicesToAnalyze = results.Select(r => new 
        { 
            Port = r.Port, 
            Service = r.Service, 
            Details = r.Details 
        }).ToList();

        var servicesJson = JsonSerializer.Serialize(servicesToAnalyze);

        var requestBody = new
        {
            model = model,
            messages = new[]
            {
                new
                {
                    role = "system",
                    content = "Tu es un expert en cybersécurité et pentesting. Je vais te fournir un JSON contenant une liste de services détectés sur une cible. Ton rôle est d'analyser chaque service et de fournir des instructions techniques précises pour l'auditer ou l'exploiter (commandes nmap, hydra, metasploit, vulnérabilités courantes associées à la version, etc.). Retourne UNIQUEMENT un JSON valide (sans balises markdown) sous la forme d'un tableau d'objets : [{'port': int, 'explanation': string}]. Le champ 'explanation' doit être direct, professionnel et orienté 'Red Team'."
                },
                new
                {
                    role = "user",
                    content = servicesJson
                }
            },
            temperature = 0.3
        };

        try
        {
            var requestContent = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

            var response = await _httpClient.PostAsync(apiUrl, requestContent);
            response.EnsureSuccessStatusCode();

            var responseString = await response.Content.ReadAsStringAsync();
            var aiResponse = JsonSerializer.Deserialize<AiResponse>(responseString);

            if (aiResponse?.Choices != null && aiResponse.Choices.Length > 0)
            {
                var content = aiResponse.Choices[0].Message.Content;
                
                // Nettoyage au cas où l'IA mettrait du markdown
                content = content.Replace("```json", "").Replace("```", "").Trim();

                var explanations = JsonSerializer.Deserialize<List<AiExplanationResult>>(content);

                if (explanations != null)
                {
                    foreach (var explanation in explanations)
                    {
                        var scanResult = results.FirstOrDefault(r => r.Port == explanation.Port);
                        if (scanResult != null)
                        {
                            scanResult.AiExplanation = explanation.Explanation;
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during AI analysis");
            // On ne bloque pas l'appli si l'IA échoue
        }
    }

    public bool HasApiKey()
    {
        return !string.IsNullOrEmpty(_settingsService.GetSettings().AiApiKey);
    }

    // Classes internes pour le mapping JSON de l'API OpenAI/DeepSeek
    private class AiResponse
    {
        [JsonPropertyName("choices")]
        public AiChoice[] Choices { get; set; }
    }

    private class AiChoice
    {
        [JsonPropertyName("message")]
        public AiMessage Message { get; set; }
    }

    private class AiMessage
    {
        [JsonPropertyName("content")]
        public string Content { get; set; }
    }

    private class AiExplanationResult
    {
        [JsonPropertyName("port")]
        public int Port { get; set; }

        [JsonPropertyName("explanation")]
        public string Explanation { get; set; }
    }
}
