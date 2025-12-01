using Microsoft.Data.Sqlite;

public class HistoryItem
{
    public int Id { get; set; }
    public string Time { get; set; } = "";
    public long GroupScanId { get; set; }
    public string Target { get; set; } = "";
    public string Summary { get; set; } = "";
}

public class HistoryService
{
    private readonly string _dbPath = "scans.sqlite";

    public List<HistoryItem> GetGroup()
    {
        var list = new List<HistoryItem>();

        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT Id, Time, GroupScanId, Target, Service, Port 
            FROM ScanResults 
            ORDER BY GroupScanId DESC;
        ";

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new HistoryItem
            {
                Id = reader.GetInt32(0),
                Time = reader.GetString(1),
                GroupScanId = reader.GetInt64(2),
                Target = reader.GetString(3),
                Summary = $"Port {reader.GetInt32(5)} : {reader.GetString(4)}"
            });
        }

        return list;
    }


    // Fonction pour supprimer une ligne de la table
    public void DeleteRow(int id)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            DELETE 
            FROM ScanResults
            WHERE id = @id
        ";

        // On remplace id avec la valeur transmise depuis History.razor
        cmd.Parameters.AddWithValue("@id", id);
        cmd.ExecuteNonQuery();
    }

    // Fonction pour récupérer le système d'exploitation par GroupScanId
    public string GetOsByGroupScanId(long groupScanId)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT OS 
            FROM ScanGroups 
            WHERE GroupScanId = @groupScanId;
        ";
        cmd.Parameters.AddWithValue("@groupScanId", groupScanId);

        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            return reader.GetString(0);
        }

        return "None";
    }
}
