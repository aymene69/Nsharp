using System.Text;
using NsharpBlazor.Models;

namespace NsharpBlazor.Services;

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
        
        sb.AppendLine("0 0 1 rg");
        sb.AppendLine("/F1 24 Tf");
        sb.AppendLine("80 800 Td");
        sb.AppendLine("(RAPPORT DE SCAN RESEAU) Tj");
        
        sb.AppendLine("0 -35 Td");
        sb.AppendLine("0.4 0.4 0.4 rg");
        sb.AppendLine("/F2 11 Tf");
        sb.AppendLine("(Analyse de securite reseau - Nsharp Scanner v1.0) Tj");
        
        sb.AppendLine("0 -40 Td");
        sb.AppendLine("0 0 0 rg");
        sb.AppendLine("/F1 14 Tf");
        sb.AppendLine("(___________________________________________________________) Tj");
        
        sb.AppendLine("0 -30 Td");
        sb.AppendLine("0 0 1 rg");
        sb.AppendLine("/F1 14 Tf");
        sb.AppendLine("(INFORMATIONS DU SCAN) Tj");
        
        sb.AppendLine("0 -20 Td");
        sb.AppendLine("0 0 0 rg");
        sb.AppendLine("/F2 10 Tf");
        sb.AppendLine($"(  Cible scannee       : {Clean(target)}) Tj");
        
        sb.AppendLine("0 -14 Td");
        sb.AppendLine($"(  Date du scan        : {DateTime.Now:yyyy-MM-dd HH:mm:ss}) Tj");
        
        sb.AppendLine("0 -14 Td");
        sb.AppendLine($"(  Genere par          : Nsharp Scanner) Tj");
        
        if (!string.IsNullOrEmpty(osDetection))
        {
            sb.AppendLine("0 -14 Td");
            sb.AppendLine("0 0.5 0 rg");
            sb.AppendLine($"(  OS detecte          : {Clean(osDetection)}) Tj");
            sb.AppendLine("0 0 0 rg");
        }
        
        sb.AppendLine("0 -30 Td");
        sb.AppendLine("0 0 1 rg");
        sb.AppendLine("/F1 14 Tf");
        sb.AppendLine("(RESUME) Tj");
        
        sb.AppendLine("0 -20 Td");
        sb.AppendLine("0 0 0 rg");
        sb.AppendLine("/F1 11 Tf");
        if (scanResults.Count > 0)
        {
            sb.AppendLine("0 0.5 0 rg");
            sb.AppendLine($"(  {scanResults.Count} port\\(s\\) ouvert\\(s\\) detecte\\(s\\)) Tj");
        }
        else
        {
            sb.AppendLine("0.7 0 0 rg");
            sb.AppendLine("(  Aucun port ouvert detecte) Tj");
        }
        
        sb.AppendLine("0 -30 Td");
        sb.AppendLine("0 0 1 rg");
        sb.AppendLine("/F1 14 Tf");
        sb.AppendLine("(PORTS OUVERTS DETAILLES) Tj");
        sb.AppendLine("0 0 0 rg");
        
        if (scanResults.Count == 0)
        {
            sb.AppendLine("0 -20 Td");
            sb.AppendLine("0.5 0.5 0.5 rg");
            sb.AppendLine("/F2 10 Tf");
            sb.AppendLine("(  Aucun port ouvert n'a ete detecte lors du scan.) Tj");
            sb.AppendLine("0 -12 Td");
            sb.AppendLine("(  Verifiez la cible et les ports specifies.) Tj");
        }
        else
        {
            var maxPorts = Math.Min(scanResults.Count, 8);
            for (int i = 0; i < maxPorts; i++)
            {
                var r = scanResults[i];
                
                sb.AppendLine("0 -25 Td");
                sb.AppendLine("0 0 1 rg");
                sb.AppendLine("/F1 12 Tf");
                sb.AppendLine($"(Port {r.Port}  |  {Clean(r.Service)}) Tj");
                
                sb.AppendLine("0 -16 Td");
                sb.AppendLine("0 0 0 rg");
                sb.AppendLine("/F1 9 Tf");
                sb.AppendLine("(  Protocole :) Tj");
                sb.AppendLine("0 -11 Td");
                sb.AppendLine("/F2 9 Tf");
                sb.AppendLine($"(    {Clean(r.Protocol)}) Tj");
                
                sb.AppendLine("0 -13 Td");
                sb.AppendLine("/F1 9 Tf");
                sb.AppendLine("(  Details :) Tj");
                
                var detailLines = WrapText(r.Details, 75);
                foreach (var line in detailLines.Take(3))
                {
                    sb.AppendLine("0 -11 Td");
                    sb.AppendLine("/F2 8 Tf");
                    sb.AppendLine($"(    {Clean(line)}) Tj");
                }
                
                sb.AppendLine("0 -13 Td");
                sb.AppendLine("0.8 0.4 0 rg");
                sb.AppendLine("/F1 9 Tf");
                sb.AppendLine("(  Recommandation :) Tj");
                sb.AppendLine("0 0 0 rg");
                
                var adviceLines = WrapText(r.Advice, 75);
                foreach (var line in adviceLines.Take(2))
                {
                    sb.AppendLine("0 -11 Td");
                    sb.AppendLine("/F2 8 Tf");
                    sb.AppendLine($"(    {Clean(line)}) Tj");
                }
                
                sb.AppendLine("0 -8 Td");
                sb.AppendLine("0.7 0.7 0.7 rg");
                sb.AppendLine("/F2 8 Tf");
                sb.AppendLine("(  -------------------------------------------------------) Tj");
                sb.AppendLine("0 0 0 rg");
            }
            
            if (scanResults.Count > maxPorts)
            {
                sb.AppendLine("0 -18 Td");
                sb.AppendLine("0.5 0.5 0.5 rg");
                sb.AppendLine("/F2 9 Tf");
                sb.AppendLine($"(  ... et {scanResults.Count - maxPorts} autre\\(s\\) port\\(s\\) ouvert\\(s\\)) Tj");
            }
        }
        
        sb.AppendLine("0 -30 Td");
        sb.AppendLine("0.5 0.5 0.5 rg");
        sb.AppendLine("/F2 8 Tf");
        sb.AppendLine($"(Rapport genere le {DateTime.Now:dd/MM/yyyy} a {DateTime.Now:HH:mm:ss}) Tj");
        
        sb.AppendLine("ET");
        return sb.ToString();
    }

    private string Clean(string text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text
            .Replace("\\", "\\\\")
            .Replace("(", "\\(")
            .Replace(")", "\\)")
            .Replace("\r", "")
            .Replace("\n", " ")
            .Replace("\t", " ");
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

