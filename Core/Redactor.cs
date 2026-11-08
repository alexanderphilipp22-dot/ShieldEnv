using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShieldEnv.Core;

public sealed record MapEntry(string Token, string Secret, string Kind, string File, int Line, int Offset);

public sealed class MapDocument
{
    public int Version { get; set; } = 1;
    public List<MapEntry> Entries { get; set; } = new();
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = false)]
[JsonSerializable(typeof(MapDocument))]
[JsonSerializable(typeof(List<SecretMatch>))]
public sealed partial class MapJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Issues globally unique redaction tokens (e.g. <c>[REDAC_OPENAI_KEY_01]</c>)
/// across all files so the restore map never has ambiguous entries.
/// </summary>
public sealed class TokenIssuer
{
    private readonly object _gate = new();
    private readonly Dictionary<string, int> _counts = new(StringComparer.Ordinal);

    public string Issue(string kind)
    {
        lock (_gate)
        {
            _counts.TryGetValue(kind, out int count);
            count++;
            _counts[kind] = count;
            return $"[REDAC_{kind}_{count:D2}]";
        }
    }
}

public static class Redactor
{
    private const string TokenPrefix = "[REDAC_";

    public static (string Redacted, IReadOnlyList<MapEntry> Entries) Redact(
        string text,
        string filePath,
        IReadOnlyList<SecretMatch> matches,
        TokenIssuer issuer)
    {
        List<SecretMatch> ordered = matches.OrderBy(m => m.Offset).ThenBy(m => m.Length).ToList();
        var builder = new StringBuilder(text.Length + ordered.Count * 24);
        var entries = new List<MapEntry>(ordered.Count);

        int cursor = 0;
        foreach (SecretMatch match in ordered)
        {
            if (match.Offset < cursor)
                continue;

            builder.Append(text, cursor, match.Offset - cursor);
            string token = issuer.Issue(match.Kind);
            builder.Append(token);
            entries.Add(new MapEntry(token, match.Value, match.Kind, filePath, match.Line, match.Offset));
            cursor = match.Offset + match.Length;
        }

        builder.Append(text, cursor, text.Length - cursor);
        return (builder.ToString(), entries);
    }

    public static string Restore(string text, IReadOnlyCollection<MapEntry> entries)
    {
        if (text.IndexOf(TokenPrefix, StringComparison.Ordinal) < 0)
            return text;

        var map = new Dictionary<string, string>(entries.Count, StringComparer.Ordinal);
        foreach (MapEntry entry in entries)
            map[entry.Token] = entry.Secret;

        var builder = new StringBuilder(text.Length);
        int i = 0;
        while (i < text.Length)
        {
            int start = text.IndexOf(TokenPrefix, i, StringComparison.Ordinal);
            if (start < 0)
            {
                builder.Append(text, i, text.Length - i);
                break;
            }

            builder.Append(text, i, start - i);

            int end = text.IndexOf(']', start + TokenPrefix.Length);
            if (end < 0)
            {
                builder.Append(text, start, text.Length - start);
                break;
            }

            string token = text.Substring(start, end - start + 1);
            if (map.TryGetValue(token, out string? secret))
                builder.Append(secret);
            else
                builder.Append(token);

            i = end + 1;
        }

        return builder.ToString();
    }

    public static string Serialize(IReadOnlyList<MapEntry> entries) =>
        JsonSerializer.Serialize(new MapDocument { Entries = entries.ToList() }, MapJsonContext.Default.MapDocument);

    public static IReadOnlyList<MapEntry> Deserialize(string json) =>
        JsonSerializer.Deserialize(json, MapJsonContext.Default.MapDocument)?.Entries ?? new List<MapEntry>();
}
