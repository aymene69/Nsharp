using System.Text.Json;

namespace Nsharp.Services;

public class UserSettings
{
    public string AiApiKey { get; set; } = "";
    public string AiModel { get; set; } = "deepseek-chat";
}

public class SettingsService
{
    private readonly string _filePath;
    private UserSettings _settings;
    private readonly ILogger<SettingsService> _logger;

    public SettingsService(ILogger<SettingsService> logger)
    {
        _logger = logger;
        _filePath = Path.Combine(Directory.GetCurrentDirectory(), "user-settings.json");
        LoadSettings();
    }

    public UserSettings GetSettings() => _settings;

    public void SaveSettings(string apiKey, string model)
    {
        _settings.AiApiKey = apiKey;
        _settings.AiModel = model;

        try
        {
            var json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_filePath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error saving settings");
        }
    }

    private void LoadSettings()
    {
        try
        {
            if (File.Exists(_filePath))
            {
                var json = File.ReadAllText(_filePath);
                _settings = JsonSerializer.Deserialize<UserSettings>(json) ?? new UserSettings();
            }
            else
            {
                _settings = new UserSettings();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading settings");
            _settings = new UserSettings();
        }
    }
}

