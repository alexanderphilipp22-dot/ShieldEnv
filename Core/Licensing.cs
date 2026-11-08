using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShieldEnv.Core;

public sealed class LicensePayload
{
    public string LicenseId { get; set; } = "";
    public string Licensee { get; set; } = "";
    public string Product { get; set; } = "";
    public string Edition { get; set; } = "pro";
    public DateTimeOffset IssuedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public string MachineId { get; set; } = "";
    public List<string> Features { get; set; } = new();
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(LicensePayload))]
internal sealed partial class LicenseJsonContext : JsonSerializerContext
{
}

public sealed record LicenseResult(bool IsValid, bool IsPro, string Message, LicensePayload? Payload);

/// <summary>
/// Offline license validation using RSA public-key cryptography (RSACng).
/// A license key is <c>LEAK1.&lt;payloadB64Url&gt;.&lt;signatureB64Url&gt;</c>, where the
/// signature is RSASSA-PSS (SHA-256) over the raw payload bytes. Validation is
/// fully offline: only the embedded public key is needed.
/// </summary>
public static class Licensing
{
    private const string KeyPrefix = "LEAK1.";
    private const string ProductName = "leakguard";

    // RSA-2048 public key (SubjectPublicKeyInfo, base64 DER) used to verify
    // license signatures. Replace with your own vendor public key. The matching
    // private key must never ship with the binary.
    private const string PublicKeySpkiBase64 =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsCiWS1iEY4d4aYEzhaxaZYZ0uH4g5lpwp5PPrdsNhyDmF45Ar5Z9oMSmy/uSpAxM7Q3xMxlOVr/Fdvxwfc4m1QXmRHPsD5hwRCvmzpdUYBfjZhBqLW+Ye5/RDRXrMiHuDYFo0ZDrbI3r4NFWSImJZb4fGOS4b1yqoF5oqoRCeKtLUfNGep+kjKvxtJMdgIJUha/t8K0EQeVrKqtR2vslZcXOeshLDNlJVwz7C46hTpAN6wZmF1gfyuuNNDkvSqyDKTo+wA2jhxX1Py1zeq2DQNsc2sOYLHA2yOZ5kdU+O99NWDngFKZIR4r82+NFvzVX62z7BuOZYyT/FYE6dmKeeQIDAQAB";

    /// <summary>Absolute path of the local license file (next to the executable).</summary>
    public static string LicenseFilePath => Path.Combine(AppContext.BaseDirectory, "leakguard.lic");

    public static LicenseResult LoadLocalLicense()
    {
        try
        {
            if (!File.Exists(LicenseFilePath))
                return new LicenseResult(false, false, "No license found — running in Free mode.", null);

            string key = File.ReadAllText(LicenseFilePath).Trim();
            LicenseResult result = Validate(key, DateTimeOffset.UtcNow);
            return result.IsValid
                ? result
                : new LicenseResult(false, false, result.Message + " Running in Free mode.", null);
        }
        catch (Exception ex)
        {
            return new LicenseResult(false, false, $"License could not be read: {ex.Message}. Running in Free mode.", null);
        }
    }

    public static LicenseResult Activate(string licenseKey)
    {
        LicenseResult result = Validate(licenseKey, DateTimeOffset.UtcNow);
        if (!result.IsValid)
            return result;

        try
        {
            File.WriteAllText(LicenseFilePath, licenseKey.Trim());
        }
        catch (Exception ex)
        {
            return new LicenseResult(false, false, $"License is valid but could not be saved: {ex.Message}", null);
        }

        return result;
    }

    public static LicenseResult Validate(string licenseKey, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(licenseKey))
            return Invalid("License key is empty.");

        licenseKey = licenseKey.Trim();

        if (!licenseKey.StartsWith(KeyPrefix, StringComparison.Ordinal))
            return Invalid("Invalid license format.");

        string[] parts = licenseKey[KeyPrefix.Length..].Split('.');
        if (parts.Length != 2)
            return Invalid("Invalid license format.");

        byte[] payloadBytes;
        byte[] signature;
        try
        {
            payloadBytes = Base64UrlDecode(parts[0]);
            signature = Base64UrlDecode(parts[1]);
        }
        catch
        {
            return Invalid("License key is not valid Base64.");
        }

        try
        {
            using var rsa = new RSACng();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(PublicKeySpkiBase64), out _);

            byte[] hash = SHA256.HashData(payloadBytes);
            if (!rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                return Invalid("License signature is invalid.");
        }
        catch
        {
            return Invalid("License verification failed.");
        }

        LicensePayload? payload;
        try
        {
            string json = Encoding.UTF8.GetString(payloadBytes);
            payload = JsonSerializer.Deserialize(json, LicenseJsonContext.Default.LicensePayload);
        }
        catch
        {
            return Invalid("License payload could not be parsed.");
        }

        if (payload is null)
            return Invalid("License payload is empty.");

        if (!string.Equals(payload.Product, ProductName, StringComparison.OrdinalIgnoreCase))
            return Invalid($"License is for a different product ('{payload.Product}').");

        if (payload.ExpiresAt != default && payload.ExpiresAt <= nowUtc)
            return Invalid("License has expired.");

        if (!string.IsNullOrEmpty(payload.MachineId) &&
            !string.Equals(payload.MachineId, GetMachineId(), StringComparison.Ordinal))
            return Invalid("License is bound to a different machine.");

        bool isPro =
            string.Equals(payload.Edition, "pro", StringComparison.OrdinalIgnoreCase) ||
            payload.Features.Contains("unlimited", StringComparer.OrdinalIgnoreCase);

        string message = isPro
            ? $"Pro License Active — {payload.Licensee} (expires {payload.ExpiresAt:yyyy-MM-dd})"
            : "License valid (Free edition).";

        return new LicenseResult(true, isPro, message, payload);
    }

    /// <summary>
    /// Stable machine fingerprint for optional hardware-bound licenses. Combine
    /// with additional identifiers if stronger binding is required.
    /// </summary>
    public static string GetMachineId()
    {
        string raw = $"{Environment.MachineName}|{Environment.UserName}|{Environment.OSVersion}|{Environment.ProcessorCount}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    }

    private static LicenseResult Invalid(string message) => new(false, false, message, null);

    private static byte[] Base64UrlDecode(string input)
    {
        string normalized = input.Replace('-', '+').Replace('_', '/');
        normalized += (normalized.Length % 4) switch
        {
            1 => "===",
            2 => "==",
            3 => "=",
            _ => string.Empty
        };
        return Convert.FromBase64String(normalized);
    }
}

