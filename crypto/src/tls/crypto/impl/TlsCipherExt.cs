namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>
    /// Extension of <see cref="TlsCipher"/> that reports the plaintext limits for a given ciphertext limit.
    /// </summary>
    // TODO[api] Merge into TlsCipher
    public interface TlsCipherExt
    {
        int GetPlaintextDecodeLimit(int ciphertextLimit);

        int GetPlaintextEncodeLimit(int ciphertextLimit);
    }
}
