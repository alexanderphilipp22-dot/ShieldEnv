using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using ShieldEnv.Core;

namespace ShieldEnv;

internal static class Program
{
    private const string Version = "1.1.0";

    // Free-mode (Demo) limits applied when no valid Pro license is present.
    private const int FreeMaxFiles = 64;
    private const long FreeMaxFileBytes = 1_000_000L; // 1 MB per file

    private static LicenseResult? _licenseCache;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
            return PrintRootHelp();

        string command = args[0].ToLowerInvariant();

        return command switch
        {
            "scan" => await RunScan(args[1..]),
            "clean" => await RunClean(args[1..]),
            "restore" => await RunRestore(args[1..]),
            "activate" => RunActivate(args[1..]),
            "help" or "--help" or "-h" => PrintRootHelp(),
            "--version" or "-v" => PrintVersion(),
            _ => UnknownCommand(args[0]),
        };
    }

    private static LicenseResult CurrentLicense() => _licenseCache ??= Licensing.LoadLocalLicense();

    // ------------------------------------------------------------------ scan

    private static async Task<int> RunScan(string[] args)
    {
        if (ContainsHelp(args))
            return PrintScanHelp();

        var a = new Args(args);
        string path = a.Value("--path", string.Empty, out bool hasPath);
        if (!hasPath || string.IsNullOrWhiteSpace(path))
        {
            Console.Error.WriteLine("scan: --path <file|dir> is required.");
            return 1;
        }

        bool recursive = ParseBool(a.Value("--recursive", "true", out _), true);
        int threads = ParseInt(a.Value("--threads", Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture), out _), Environment.ProcessorCount);
        double entropy = ParseDouble(a.Value("--entropy-threshold", "4.5", out _), 4.5);
        bool json = a.Flag("--json");

        return await HandleScan(path, recursive, threads, entropy, json);
    }

    private static async Task<int> HandleScan(string path, bool recursive, int threads, double entropyThreshold, bool json)
    {
        try
        {
            LicenseResult license = CurrentLicense();
            Console.WriteLine(license.Message);

            IReadOnlyList<string> allFiles = Scanner.CollectFiles(path, recursive);
            List<string> files = ApplyLicenseLimits(allFiles, license);

            if (files.Count == 0)
            {
                Console.WriteLine("No files to scan.");
                return 0;
            }

            if (files.Count < allFiles.Count)
                Console.WriteLine($"Free mode: scanning {files.Count} of {allFiles.Count} file(s). Activate Pro for unlimited deep scan.");

            var scanner = new Scanner(entropyThreshold);
            List<SecretMatch> matches = await scanner.ScanFilesAsync(files, threads);

            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(matches, MapJsonContext.Default.ListSecretMatch));
                return 0;
            }

            foreach (SecretMatch m in matches.OrderBy(m => m.File).ThenBy(m => m.Line).ThenBy(m => m.Offset))
            {
                string entropy = m.Entropy > 0.0 ? $" entropy={m.Entropy:F2}" : string.Empty;
                Console.WriteLine($"{m.File}:{m.Line}  [{m.Kind}]{entropy}  {Preview(m.Value)}");
            }

            Console.WriteLine();
            Console.WriteLine($"{matches.Count} potential secret(s) across {files.Count} file(s).");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"scan failed: {ex.Message}");
            return 1;
        }
    }

    // ----------------------------------------------------------------- clean

    private static async Task<int> RunClean(string[] args)
    {
        if (ContainsHelp(args))
            return PrintCleanHelp();

        var a = new Args(args);
        string path = a.Value("--path", string.Empty, out bool hasPath);
        if (!hasPath || string.IsNullOrWhiteSpace(path))
        {
            Console.Error.WriteLine("clean: --path <file|dir> is required.");
            return 1;
        }

        bool recursive = ParseBool(a.Value("--recursive", "true", out _), true);
        int threads = ParseInt(a.Value("--threads", Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture), out _), Environment.ProcessorCount);
        double entropy = ParseDouble(a.Value("--entropy-threshold", "4.5", out _), 4.5);
        string map = a.Value("--map", ".leakguard.map", out _);
        string passphrase = a.Value("--passphrase", string.Empty, out _);
        bool backup = a.Flag("--backup");

        return await HandleClean(path, recursive, threads, entropy, map, passphrase, backup);
    }

    private static async Task<int> HandleClean(
        string path,
        bool recursive,
        int threads,
        double entropyThreshold,
        string mapPath,
        string passphrase,
        bool backup)
    {
        try
        {
            LicenseResult license = CurrentLicense();
            Console.WriteLine(license.Message);

            IReadOnlyList<string> allFiles = Scanner.CollectFiles(path, recursive);
            List<string> files = ApplyLicenseLimits(allFiles, license);

            if (files.Count == 0)
            {
                Console.WriteLine("No files to clean.");
                return 0;
            }

            if (files.Count < allFiles.Count)
                Console.WriteLine($"Free mode: cleaning {files.Count} of {allFiles.Count} file(s). Activate Pro for unlimited deep scan.");

            var scanner = new Scanner(entropyThreshold);
            var issuer = new TokenIssuer();
            var entries = new List<MapEntry>();
            var options = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, threads) };
            int changedFiles = 0;

            await Parallel.ForEachAsync(files, options, (file, ct) =>
            {
                try
                {
                    string? text = Scanner.ReadAllTextFast(file);
                    if (text is null)
                        return ValueTask.CompletedTask;

                    List<SecretMatch> matches = scanner.Scan(text, file);
                    if (matches.Count == 0)
                        return ValueTask.CompletedTask;

                    (string redacted, IReadOnlyList<MapEntry> fileEntries) = Redactor.Redact(text, file, matches, issuer);

                    if (backup && !File.Exists(file + ".orig"))
                        File.Copy(file, file + ".orig");

                    File.WriteAllText(file, redacted);

                    lock (entries)
                        entries.AddRange(fileEntries);

                    Interlocked.Increment(ref changedFiles);
                }
                catch (Exception)
                {
                    // Unreadable files are skipped.
                }

                return ValueTask.CompletedTask;
            });

            if (entries.Count == 0)
            {
                Console.WriteLine("No secrets found; nothing to redact.");
                return 0;
            }

            Vault.SealMap(mapPath, Redactor.Serialize(entries), ResolvePassphrase(passphrase));
            Console.WriteLine($"Redacted {entries.Count} secret(s) across {changedFiles} file(s).");
            Console.WriteLine($"Encrypted restore map: {Path.GetFullPath(mapPath)}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"clean failed: {ex.Message}");
            return 1;
        }
    }

    // --------------------------------------------------------------- restore

    private static async Task<int> RunRestore(string[] args)
    {
        if (ContainsHelp(args))
            return PrintRestoreHelp();

        var a = new Args(args);
        string path = a.Value("--path", string.Empty, out bool hasPath);
        if (!hasPath || string.IsNullOrWhiteSpace(path))
        {
            Console.Error.WriteLine("restore: --path <file|dir> is required.");
            return 1;
        }

        bool recursive = ParseBool(a.Value("--recursive", "true", out _), true);
        string map = a.Value("--map", ".leakguard.map", out _);
        string passphrase = a.Value("--passphrase", string.Empty, out _);
        bool dryRun = a.Flag("--dry-run");

        return await HandleRestore(path, recursive, map, passphrase, dryRun);
    }

    private static async Task<int> HandleRestore(string path, bool recursive, string mapPath, string passphrase, bool dryRun)
    {
        try
        {
            LicenseResult license = CurrentLicense();
            if (!license.IsPro)
            {
                Console.Error.WriteLine("restore requires a Pro license. Run 'leakguard activate --key <license_key>'.");
                return 1;
            }
            Console.WriteLine(license.Message);

            if (!File.Exists(mapPath))
            {
                Console.Error.WriteLine($"restore failed: map file not found: {mapPath}");
                return 1;
            }

            IReadOnlyList<MapEntry> entries = Redactor.Deserialize(Vault.OpenMap(mapPath, ResolvePassphrase(passphrase)));
            IReadOnlyList<string> files = Scanner.CollectFiles(path, recursive);
            var options = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount) };
            int restoredFiles = 0;

            await Parallel.ForEachAsync(files, options, (file, ct) =>
            {
                try
                {
                    string? text = Scanner.ReadAllTextFast(file);
                    if (text is null)
                        return ValueTask.CompletedTask;

                    string restored = Redactor.Restore(text, entries);
                    if (!string.Equals(restored, text, StringComparison.Ordinal))
                    {
                        if (!dryRun)
                            File.WriteAllText(file, restored);
                        Interlocked.Increment(ref restoredFiles);
                    }
                }
                catch (Exception)
                {
                    // Unreadable files are skipped.
                }

                return ValueTask.CompletedTask;
            });

            Console.WriteLine($"{(dryRun ? "Dry-run: " : string.Empty)}restored {restoredFiles} file(s) from {Path.GetFullPath(mapPath)}.");
            return 0;
        }
        catch (CryptographicException)
        {
            Console.Error.WriteLine("restore failed: wrong passphrase or corrupt map file.");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"restore failed: {ex.Message}");
            return 1;
        }
    }

    // -------------------------------------------------------------- activate

    private static int RunActivate(string[] args)
    {
        if (ContainsHelp(args))
            return PrintActivateHelp();

        var a = new Args(args);
        string key = a.Value("--key", string.Empty, out bool hasKey);
        if (!hasKey || string.IsNullOrWhiteSpace(key))
        {
            Console.Error.WriteLine("activate: --key <license_key> is required.");
            return 1;
        }

        LicenseResult result = Licensing.Activate(key);
        Console.WriteLine(result.Message);
        if (result.IsValid)
            Console.WriteLine($"License saved to: {Licensing.LicenseFilePath}");

        return result.IsValid ? 0 : 1;
    }

    // ---------------------------------------------------------------- helpers

    private static List<string> ApplyLicenseLimits(IReadOnlyList<string> files, LicenseResult license)
    {
        if (license.IsPro)
            return files.ToList();

        var result = new List<string>(Math.Min(files.Count, FreeMaxFiles));
        foreach (string file in files)
        {
            if (result.Count >= FreeMaxFiles)
                break;

            long length;
            try
            {
                length = new FileInfo(file).Length;
            }
            catch
            {
                continue;
            }

            if (length <= FreeMaxFileBytes)
                result.Add(file);
        }

        return result;
    }

    private static string ResolvePassphrase(string? passphrase)
    {
        if (!string.IsNullOrWhiteSpace(passphrase))
            return passphrase;

        string? env = Environment.GetEnvironmentVariable("LEAKGUARD_PASSPHRASE");
        if (!string.IsNullOrWhiteSpace(env))
            return env;

        Console.Error.WriteLine("warning: using default development passphrase (set LEAKGUARD_PASSPHRASE or --passphrase).");
        return "leakguard-local-dev";
    }

    private static string Preview(string value) => value.Length <= 64 ? value : value[..61] + "...";

    private static bool ParseBool(string value, bool fallback) => bool.TryParse(value, out bool b) ? b : fallback;

    private static int ParseInt(string value, int fallback) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int n) && n > 0 ? n : fallback;

    private static double ParseDouble(string value, double fallback) =>
        double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out double d) ? d : fallback;

    private static bool ContainsHelp(string[] args) => args.Any(a => a is "--help" or "-h");

    private static int UnknownCommand(string command)
    {
        Console.Error.WriteLine($"leakguard: unknown command '{command}'.");
        Console.Error.WriteLine("Run 'leakguard --help' for usage.");
        return 1;
    }

    private static int PrintVersion()
    {
        Console.WriteLine($"leakguard {Version}");
        return 0;
    }

    private static int PrintRootHelp()
    {
        Console.WriteLine(
            """
            leakguard — ShieldEnv / LeakGuard
            Offline secret scanner, redactor, and restorer.

            Usage:
              leakguard <command> [options]

            Commands:
              scan       Scan files and report detected secrets without modifying them.
              clean      Redact detected secrets in place and write an encrypted restore map.
              restore    Restore redacted secrets from an encrypted map. (Pro only)
              activate   Verify and install a Pro license key.

            Global:
              --help, -h      Show help.
              --version, -v   Show version.

            Run 'leakguard <command> --help' for command-specific options.
            """);
        return 0;
    }

    private static int PrintScanHelp()
    {
        Console.WriteLine(
            """
            Usage:
              leakguard scan --path <file|dir> [options]

            Options:
              --path <file|dir>          File or directory to scan. (required)
              --recursive <true|false>   Recurse into subdirectories. (default: true)
              --threads <n>              Maximum files scanned in parallel. (default: CPU count)
              --entropy-threshold <n>    Shannon entropy cutoff for high-entropy tokens. (default: 4.5)
              --json                     Emit results as JSON.
            """);
        return 0;
    }

    private static int PrintCleanHelp()
    {
        Console.WriteLine(
            """
            Usage:
              leakguard clean --path <file|dir> [options]

            Options:
              --path <file|dir>          File or directory to clean. (required)
              --recursive <true|false>   Recurse into subdirectories. (default: true)
              --threads <n>              Maximum files processed in parallel. (default: CPU count)
              --entropy-threshold <n>    Shannon entropy cutoff for high-entropy tokens. (default: 4.5)
              --map <path>               Encrypted restore map path. (default: .leakguard.map)
              --passphrase <secret>      Map key passphrase. (default: LEAKGUARD_PASSPHRASE env var)
              --backup                   Write a .orig backup before overwriting.
            """);
        return 0;
    }

    private static int PrintRestoreHelp()
    {
        Console.WriteLine(
            """
            Usage:
              leakguard restore --path <file|dir> [options]

            Options:
              --path <file|dir>          File or directory to restore. (required)
              --recursive <true|false>   Recurse into subdirectories. (default: true)
              --map <path>               Encrypted restore map path. (default: .leakguard.map)
              --passphrase <secret>      Map key passphrase. (default: LEAKGUARD_PASSPHRASE env var)
              --dry-run                  Report restorations without writing files.
            """);
        return 0;
    }

    private static int PrintActivateHelp()
    {
        Console.WriteLine(
            """
            Usage:
              leakguard activate --key <license_key>

            Options:
              --key <license_key>   Signed Pro license key (required).

            On success the license is saved next to the executable as leakguard.lic.
            """);
        return 0;
    }

    private sealed class Args
    {
        private readonly string[] _items;

        public Args(string[] items) => _items = items;

        public bool Flag(string name) => Array.IndexOf(_items, name) >= 0;

        public string Value(string name, string fallback, out bool present)
        {
            for (int i = 0; i < _items.Length; i++)
            {
                string item = _items[i];
                if (item == name)
                {
                    present = true;
                    if (i + 1 < _items.Length && !_items[i + 1].StartsWith("--", StringComparison.Ordinal))
                        return _items[i + 1];
                    return fallback;
                }

                if (item.StartsWith(name + "=", StringComparison.Ordinal))
                {
                    present = true;
                    return item[(name.Length + 1)..];
                }
            }

            present = false;
            return fallback;
        }
    }
}
