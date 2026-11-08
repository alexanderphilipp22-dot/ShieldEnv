using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ShieldEnv.Core;

/// <summary>
/// Local AES-256-GCM key derivation and encryption for the <c>.leakguard.map</c> file.
/// Keys are derived with PBKDF2 (SHA-256) from a user-supplied passphrase plus a
/// per-file random salt. The on-disk layout is:
///   magic(4) | version(1) | iterations(4 LE) | salt(16) | nonce(12) | tag(16) | ciphertext
/// </summary>
public static class Vault
{
    private static readonly byte[] Magic = "LGMP"u8.ToArray();
    private const byte Version = 1;

    public const int SaltSize = 16;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int KeySize = 32;
    public const int DefaultIterations = 600_000;

    public static byte[] DeriveKey(string passphrase, ReadOnlySpan<byte> salt, int iterations)
    {
        byte[] password = Encoding.UTF8.GetBytes(passphrase);
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, KeySize);
    }

    public static void SealMap(string path, string plaintext, string passphrase, int iterations = DefaultIterations)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] key = DeriveKey(passphrase, salt, iterations);
        byte[] plain = Encoding.UTF8.GetBytes(plaintext);
        byte[] cipher = new byte[plain.Length];
        byte[] tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        // Salt doubles as additional authenticated data so tampering is detected too.
        aes.Encrypt(nonce, plain, cipher, tag, salt);

        using var stream = File.Create(path);
        stream.Write(Magic);
        stream.WriteByte(Version);

        Span<byte> iterationBytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(iterationBytes, iterations);
        stream.Write(iterationBytes);

        stream.Write(salt);
        stream.Write(nonce);
        stream.Write(tag);
        stream.Write(cipher);
    }

    public static string OpenMap(string path, string passphrase)
    {
        using var stream = File.OpenRead(path);

        Span<byte> magic = stackalloc byte[Magic.Length];
        stream.ReadExactly(magic);
        if (!magic.SequenceEqual(Magic))
            throw new InvalidDataException("Not a LeakGuard map file.");

        int version = stream.ReadByte();
        if (version != Version)
            throw new InvalidDataException($"Unsupported map version: {version}");

        Span<byte> iterationBytes = stackalloc byte[4];
        stream.ReadExactly(iterationBytes);
        int iterations = BinaryPrimitives.ReadInt32LittleEndian(iterationBytes);

        byte[] salt = new byte[SaltSize];
        byte[] nonce = new byte[NonceSize];
        byte[] tag = new byte[TagSize];
        stream.ReadExactly(salt);
        stream.ReadExactly(nonce);
        stream.ReadExactly(tag);

        int cipherLength = checked((int)(stream.Length - stream.Position));
        byte[] cipher = new byte[cipherLength];
        stream.ReadExactly(cipher);

        byte[] key = DeriveKey(passphrase, salt, iterations);
        byte[] plain = new byte[cipherLength];

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, cipher, tag, plain, salt);

        return Encoding.UTF8.GetString(plain);
    }
}
