namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>
    /// Extension of <see cref="TlsCipher"/> that reports the plaintext limits for a given ciphertext limit.
    /// </summary>
    // TODO[api] Merge into TlsCipher
    public interface TlsCipherExt
    {
        /// <summary>
        /// Get the maximum length of plaintext that a ciphertext of at most the given length can decode to.
        /// </summary>
        /// <param name="ciphertextLimit">The limit on the length of the ciphertext.</param>
        /// <returns>The limit on the length of the plaintext.</returns>
        int GetPlaintextDecodeLimit(int ciphertextLimit);

        /// <summary>
        /// Get the maximum length of plaintext that can be encoded without the ciphertext exceeding a limit.
        /// </summary>
        /// <param name="ciphertextLimit">The limit on the length of the ciphertext.</param>
        /// <returns>The limit on the length of the plaintext.</returns>
        int GetPlaintextEncodeLimit(int ciphertextLimit);
    }
}
