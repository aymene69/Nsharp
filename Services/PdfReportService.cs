using System.Text;
using Nsharp.Models;

namespace Nsharp.Services;

public class PdfReportService
{
    public async Task<string> GenerateReportAsync(List<ScanResult> scanResults, string target, string? osDetection = null)
    {
        var fileName = $"scan_report_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
        var filePath = Path.Combine(Path.GetTempPath(), fileName);

        await Task.Run(() =>
        {
            var pdf = new StringBuilder();
            var objects = new List<long>();
            
            pdf.AppendLine("%PDF-1.4");
            pdf.AppendLine("%âãÏÓ");
            
            objects.Add(pdf.Length);
            pdf.AppendLine("1 0 obj");
            pdf.AppendLine("<< /Type /Catalog /Pages 2 0 R >>");
            pdf.AppendLine("endobj");
            
            objects.Add(pdf.Length);
            pdf.AppendLine("2 0 obj");
            pdf.AppendLine("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
            pdf.AppendLine("endobj");
            
            var content = CreateContent(scanResults, target, osDetection);
            var contentBytes = Encoding.Latin1.GetBytes(content);
            
            objects.Add(pdf.Length);
            pdf.AppendLine("3 0 obj");
            pdf.AppendLine("<<");
            pdf.AppendLine("/Type /Page");
            pdf.AppendLine("/Parent 2 0 R");
            pdf.AppendLine("/MediaBox [0 0 595 842]");
            pdf.AppendLine("/Contents 4 0 R");
            pdf.AppendLine("/Resources << /Font << /F1 5 0 R /F2 6 0 R >> >>");
            pdf.AppendLine(">>");
            pdf.AppendLine("endobj");
            
            objects.Add(pdf.Length);
            pdf.AppendLine("4 0 obj");
            pdf.AppendLine($"<< /Length {contentBytes.Length} >>");
            pdf.AppendLine("stream");
            pdf.Append(content);
            pdf.AppendLine("endstream");
            pdf.AppendLine("endobj");
            
            objects.Add(pdf.Length);
            pdf.AppendLine("5 0 obj");
            pdf.AppendLine("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
            pdf.AppendLine("endobj");
            
            objects.Add(pdf.Length);
            pdf.AppendLine("6 0 obj");
            pdf.AppendLine("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
            pdf.AppendLine("endobj");
            
            var xrefPos = pdf.Length;
            pdf.AppendLine("xref");
            pdf.AppendLine($"0 {objects.Count + 1}");
            pdf.AppendLine("0000000000 65535 f ");
            foreach (var pos in objects)
            {
                pdf.AppendLine($"{pos:D10} 00000 n ");
            }
            
            pdf.AppendLine("trailer");
            pdf.AppendLine($"<< /Size {objects.Count + 1} /Root 1 0 R >>");
            pdf.AppendLine("startxref");
            pdf.AppendLine(xrefPos.ToString());
            pdf.AppendLine("%%EOF");
            
            File.WriteAllText(filePath, pdf.ToString(), Encoding.Latin1);
        });

        return filePath;
    }

    private string CreateContent(List<ScanResult> scanResults, string target, string? osDetection)
    {
        var sb = new StringBuilder();
        sb.AppendLine("BT");
        
        // En-tête
        sb.AppendLine("0 0 1 rg"); // Bleu
        sb.AppendLine("/F1 24 Tf");
        sb.AppendLine("50 800 Td");
        sb.AppendLine("(RAPPORT D'AUDIT NSHARP) Tj");
        
        sb.AppendLine("0 -25 Td");
        sb.AppendLine("0.3 0.3 0.3 rg"); // Gris foncé
        sb.AppendLine("/F2 10 Tf");
        sb.AppendLine("(Analyse de securite automatisee et intelligence artificielle) Tj");
        
        sb.AppendLine("0 -40 Td");
        sb.AppendLine("0 0 0 rg"); // Noir
        sb.AppendLine("/F1 14 Tf");
        sb.AppendLine("(CIBLE DE L'AUDIT) Tj");
        
        sb.AppendLine("0 -20 Td");
        sb.AppendLine("/F2 11 Tf");
        sb.AppendLine($"(IP Cible : {Clean(target)}) Tj");
        
        sb.AppendLine("0 -15 Td");
        sb.AppendLine($"(Date     : {DateTime.Now:yyyy-MM-dd HH:mm:ss}) Tj");
        
        if (!string.IsNullOrEmpty(osDetection))
        {
            sb.AppendLine("0 -15 Td");
            sb.AppendLine($"(OS       : {Clean(osDetection)}) Tj");
        }
        
        sb.AppendLine("0 -40 Td");
        sb.AppendLine("0 0.4 0.8 rg"); // Bleu clair
        sb.AppendLine("/F1 14 Tf");
        sb.AppendLine("(RESULTATS DETAILLES) Tj");
        sb.AppendLine("0 0 0 rg");

        if (scanResults.Count == 0)
        {
            sb.AppendLine("0 -30 Td");
            sb.AppendLine("/F2 11 Tf");
            sb.AppendLine("(Aucune vulnerabilite ou port ouvert detecte.) Tj");
        }
        else
        {
            var maxPorts = Math.Min(scanResults.Count, 6); // Max 6 ports pour tenir sur une page simple (limitation PDF brut)
            for (int i = 0; i < maxPorts; i++)
            {
                var r = scanResults[i];
                
                sb.AppendLine("0 -35 Td");
                
                // Port header
                sb.AppendLine("0 0 0.5 rg"); // Bleu foncé
                sb.AppendLine("/F1 12 Tf");
                sb.AppendLine($"(PORT {r.Port} - {Clean(r.Service).ToUpper()}) Tj");
                
                // Status badge simulation
                sb.AppendLine("200 0 Td");
                sb.AppendLine("0 0.6 0 rg"); // Vert
                sb.AppendLine("/F2 10 Tf");
                sb.AppendLine("(OUVERT) Tj");
                sb.AppendLine("-200 0 Td"); // Reset X

                // Détails
                sb.AppendLine("0 -15 Td");
                sb.AppendLine("0 0 0 rg"); // Noir
                sb.AppendLine("/F2 9 Tf");
                sb.AppendLine($"(Protocole: {Clean(r.Protocol)}) Tj");
                
                // Analyse IA ou Conseil
                sb.AppendLine("0 -15 Td");
                sb.AppendLine("0.8 0.2 0.2 rg"); // Rouge brique
                sb.AppendLine("/F1 10 Tf");
                sb.AppendLine("(ANALYSE DE SECURITE & EXPLOITATION :) Tj");
                sb.AppendLine("0 0 0 rg"); // Noir

                var explanationText = !string.IsNullOrEmpty(r.AiExplanation) ? r.AiExplanation : r.Advice;
                // Nettoyage emojis pour PDF simple
                explanationText = CleanEmojis(explanationText);
                
                var lines = WrapText(explanationText, 85);
                var maxLines = Math.Min(lines.Count, 5); // Limiter à 5 lignes pour la mise en page
                
                foreach (var line in lines.Take(maxLines))
                {
                    sb.AppendLine("0 -12 Td");
                    sb.AppendLine("/F2 9 Tf");
                    sb.AppendLine($"({Clean(line)}) Tj");
                }
                
                // Séparateur
                sb.AppendLine("0 -10 Td");
                sb.AppendLine("0.8 0.8 0.8 rg");
                sb.AppendLine("/F2 8 Tf");
                sb.AppendLine("(____________________________________________________________________________________) Tj");
            }
            
            if (scanResults.Count > maxPorts)
            {
                sb.AppendLine("0 -30 Td");
                sb.AppendLine("0.5 0.5 0.5 rg");
                sb.AppendLine("/F2 10 Tf");
                sb.AppendLine($"(... et {scanResults.Count - maxPorts} autres ports non affiches sur cette page de synthese.) Tj");
            }
        }
        
        sb.AppendLine("ET");
        return sb.ToString();
    }

    private string Clean(string text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        
        // Remplacement des caractères accentués basiques pour Latin1
        text = text
            .Replace("é", "e")
            .Replace("è", "e")
            .Replace("ê", "e")
            .Replace("à", "a")
            .Replace("ç", "c")
            .Replace("ù", "u")
            .Replace("î", "i")
            .Replace("ï", "i")
            .Replace("ô", "o");

        return text
            .Replace("\\", "\\\\")
            .Replace("(", "\\(")
            .Replace(")", "\\)")
            .Replace("\r", "")
            .Replace("\n", " ")
            .Replace("\t", " ");
    }
    
    private string CleanEmojis(string text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        // Suppression basique des caractères hors plage ASCII imprimable étendu
        // Pour un PDF brut sans font unicode, c'est le plus sûr
        return new string(text.Where(c => c < 255).ToArray());
    }

    private List<string> WrapText(string text, int maxChars)
    {
        var lines = new List<string>();
        if (string.IsNullOrEmpty(text)) return lines;
        
        text = text.Replace("\r", "").Replace("\n", " ").Trim();
        var words = text.Split(' ');
        var currentLine = "";

        foreach (var word in words)
        {
            if ((currentLine + " " + word).Length <= maxChars)
            {
                currentLine += (currentLine.Length > 0 ? " " : "") + word;
            }
            else
            {
                if (currentLine.Length > 0)
                    lines.Add(currentLine);
                currentLine = word;
            }
        }

        if (currentLine.Length > 0)
            lines.Add(currentLine);

        return lines;
    }
}
