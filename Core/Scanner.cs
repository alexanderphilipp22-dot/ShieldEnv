using System.IO.MemoryMappedFiles;
using System.Text;
using System.Text.RegularExpressions;

namespace ShieldEnv.Core;

public sealed record SecretMatch(string Kind, string Value, int Offset, int Length, string File, int Line, double Entropy);

public static partial class SecretPatterns
{
    [GeneratedRegex(@"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", RegexOptions.CultureInvariant)]
    public static partial Regex AwsAccessKey();

    [GeneratedRegex(@"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b", RegexOptions.CultureInvariant)]
    public static partial Regex OpenAiKey();

    [GeneratedRegex(@"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b", RegexOptions.CultureInvariant)]
    public static partial Regex Jwt();

    [GeneratedRegex(@"\bgh[pousr]_[A-Za-z0-9]{36,}\b", RegexOptions.CultureInvariant)]
    public static partial Regex GitHubToken();

    [GeneratedRegex(@"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", RegexOptions.CultureInvariant)]
    public static partial Regex StripeKey();

    [GeneratedRegex(@"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", RegexOptions.CultureInvariant)]
    public static partial Regex SlackToken();

    [GeneratedRegex(@"\bBearer[ \t]+[A-Za-z0-9._~+/=-]{16,}", RegexOptions.CultureInvariant)]
    public static partial Regex BearerToken();

    [GeneratedRegex(@"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", RegexOptions.CultureInvariant)]
    public static partial Regex PrivateKeyHeader();
}

public sealed class Scanner
{
    private const int MinTokenLength = 16;
    private const int MaxTokenLength = 256;

    private static readonly (Regex Regex, string Kind)[] Patterns =
    {
        (SecretPatterns.AwsAccessKey(), "AWS_KEY"),
        (SecretPatterns.OpenAiKey(), "OPENAI_KEY"),
        (SecretPatterns.Jwt(), "JWT"),
        (SecretPatterns.GitHubToken(), "GITHUB_TOKEN"),
        (SecretPatterns.StripeKey(), "STRIPE_KEY"),
        (SecretPatterns.SlackToken(), "SLACK_TOKEN"),
        (SecretPatterns.BearerToken(), "BEARER"),
        (SecretPatterns.PrivateKeyHeader(), "PRIVATE_KEY"),
    };

    private readonly double _entropyThreshold;

    public Scanner(double entropyThreshold = 4.5) => _entropyThreshold = entropyThreshold;

    /// <summary>
    /// Scans a single document in memory. Regex matches take priority; entropy
    /// candidates that overlap a regex match are dropped to avoid double-reporting.
    /// </summary>
    public List<SecretMatch> Scan(string text, string filePath)
    {
        ReadOnlySpan<char> span = text.AsSpan();
        var regexMatches = new List<SecretMatch>();

        foreach (var (regex, kind) in Patterns)
        {
            foreach (var match in regex.EnumerateMatches(span))
            {
                regexMatches.Add(new SecretMatch(
                    kind,
                    span.Slice(match.Index, match.Length).ToString(),
                    match.Index,
                    match.Length,
                    filePath,
                    0,
                    0.0));
            }
        }

        regexMatches.Sort(static (a, b) => a.Offset.CompareTo(b.Offset));

        // De-duplicate overlapping regex matches (first one wins).
        var deduped = new List<SecretMatch>(regexMatches.Count);
        foreach (var match in regexMatches)
        {
            if (deduped.Count > 0 && match.Offset < deduped[^1].Offset + deduped[^1].Length)
                continue;
            deduped.Add(match);
        }

        var results = new List<SecretMatch>(deduped.Count + 16);

        // Shannon entropy sweep over maximal runs of secret-alphabet characters.
        for (int i = 0; i < span.Length;)
        {
            while (i < span.Length && !IsSecretChar(span[i]))
                i++;

            int start = i;
            while (i < span.Length && IsSecretChar(span[i]))
                i++;

            int length = i - start;
            if (length is < MinTokenLength or > MaxTokenLength)
                continue;

            ReadOnlySpan<char> token = span.Slice(start, length);
            double entropy = ShannonEntropy(token);
            if (entropy <= _entropyThreshold)
                continue;

            var candidate = new SecretMatch("ENTROPY", token.ToString(), start, length, filePath, 0, entropy);
            if (!OverlapsAny(candidate, deduped))
                results.Add(candidate);
        }

        results.AddRange(deduped);
        results.Sort(static (a, b) => a.Offset.CompareTo(b.Offset));

        int[] newlines = BuildNewlineIndex(span);
        for (int i = 0; i < results.Count; i++)
        {
            SecretMatch m = results[i];
            results[i] = m with { Line = LineOf(newlines, m.Offset) };
        }

        return results;
    }

    public async Task<List<SecretMatch>> ScanFilesAsync(
        IReadOnlyCollection<string> files,
        int maxDegreeOfParallelism,
        CancellationToken cancellationToken = default)
    {
        var results = new List<SecretMatch>();
        var options = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Max(1, maxDegreeOfParallelism),
            CancellationToken = cancellationToken
        };

        await Parallel.ForEachAsync(files, options, (file, ct) =>
        {
            try
            {
                string? text = ReadAllTextFast(file);
                if (text is null)
                    return ValueTask.CompletedTask;

                List<SecretMatch> matches = Scan(text, file);
                if (matches.Count == 0)
                    return ValueTask.CompletedTask;

                lock (results)
                    results.AddRange(matches);
            }
            catch (Exception)
            {
                // Unreadable / locked / binary files are skipped.
            }

            return ValueTask.CompletedTask;
        });

        return results;
    }

    public static IReadOnlyList<string> CollectFiles(string path, bool recursive)
    {
        var files = new List<string>();

        if (File.Exists(path))
        {
            files.Add(Path.GetFullPath(path));
            return files;
        }

        if (!Directory.Exists(path))
            throw new DirectoryNotFoundException($"Path not found: {path}");

        var enumeration = new EnumerationOptions
        {
            RecurseSubdirectories = recursive,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        foreach (string file in Directory.EnumerateFiles(path, "*", enumeration))
            files.Add(file);

        return files;
    }

    /// <summary>
    /// Reads a whole file into a UTF-16 string with a single allocation via a
    /// memory-mapped view and BOM-aware decoding. Returns <c>null</c> for binary
    /// content (detected by a NUL byte in the first 4 KiB).
    /// </summary>
    public static string? ReadAllTextFast(string path)
    {
        var info = new FileInfo(path);
        long length = info.Length;
        if (length == 0)
            return string.Empty;
        if (length > int.MaxValue)
            throw new InvalidOperationException($"File too large to memory-map: {path}");

        using var mmf = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        using var accessor = mmf.CreateViewAccessor(0, length, MemoryMappedFileAccess.Read);

        unsafe
        {
            byte* pointer = null;
            accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
            try
            {
                var bytes = new ReadOnlySpan<byte>(pointer, (int)length);

                int sniffLength = (int)Math.Min(length, 4096);
                if (bytes.Slice(0, sniffLength).IndexOf((byte)0) >= 0)
                    return null;

                return Decode(bytes);
            }
            finally
            {
                accessor.SafeMemoryMappedViewHandle.ReleasePointer();
            }
        }
    }

    private static string Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            return Encoding.UTF8.GetString(bytes.Slice(3));
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            return Encoding.Unicode.GetString(bytes.Slice(2));
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(bytes.Slice(2));
        return Encoding.UTF8.GetString(bytes);
    }

    private static int[] BuildNewlineIndex(ReadOnlySpan<char> text)
    {
        var newlines = new List<int>(Math.Min(4096, text.Length / 80 + 1));
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] == '\n')
                newlines.Add(i);
        }
        return newlines.ToArray();
    }

    private static int LineOf(int[] newlines, int offset)
    {
        int low = 0;
        int high = newlines.Length;
        while (low < high)
        {
            int mid = (low + high) / 2;
            if (newlines[mid] < offset)
                low = mid + 1;
            else
                high = mid;
        }
        return low + 1;
    }

    private static bool OverlapsAny(SecretMatch candidate, IReadOnlyList<SecretMatch> regexMatches)
    {
        foreach (SecretMatch match in regexMatches)
        {
            if (candidate.Offset < match.Offset + match.Length && match.Offset < candidate.Offset + candidate.Length)
                return true;
        }
        return false;
    }

    public static double ShannonEntropy(ReadOnlySpan<char> text)
    {
        if (text.Length < 2)
            return 0.0;

        Span<int> frequencies = stackalloc int[256];
        frequencies.Clear();

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            frequencies[c < 256 ? c : 255]++;
        }

        double inverse = 1.0 / text.Length;
        double entropy = 0.0;
        for (int i = 0; i < 256; i++)
        {
            int count = frequencies[i];
            if (count == 0)
                continue;

            double probability = count * inverse;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    // Base64/base64url/hex alphabet only. '=', ':' and whitespace act as
    // delimiters so assignment left-hand sides (e.g. "API_KEY=") are not
    // swallowed into the flagged token.
    private static bool IsSecretChar(char c) =>
        (c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') ||
        c is '+' or '/' or '-' or '_' or '.';
}
