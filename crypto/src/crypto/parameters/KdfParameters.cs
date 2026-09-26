using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Parameters for the key derivation functions that derive keying material from a shared secret and
    /// an optional block of additional input: KDF1 and KDF2 of IEEE P1363a / ISO 18033-2 (KDF2 being the
    /// ANSI X9.63 KDF, where the additional input is the SharedInfo), and the NIST SP 800 - 56A concatenation
    /// KDF(where it is the OtherInfo).
    /// </summary>
    /// <remarks>
    /// For historical reasons the additional input is referred to as the "IV".
    /// </remarks>
    public class KdfParameters
        : IDerivationParameters
    {
        private readonly byte[] m_iv;
        private readonly byte[] m_shared;

        /// <summary>Base constructor.</summary>
        /// <param name="shared">The shared secret the keying material is derived from.</param>
        /// <param name="iv">The additional input to the key derivation function, or null if there is none.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="shared"/> is null.</exception>
        public KdfParameters(byte[] shared, byte[] iv)
        {
            m_shared = shared ?? throw new ArgumentNullException(nameof(shared));
            m_iv = iv;
        }

        // TODO Consider returning a clone (and cloning in the constructor)
        /// <summary>Return the additional input to the key derivation function.</summary>
        /// <returns>The shared secret, never null.</returns>
        public byte[] GetIV() => m_iv;

        // TODO Consider returning a clone (and cloning in the constructor)
        /// <summary>Return the shared secret the keying material is derived from.</summary>
        /// <returns>The additional input, or null if there is none.</returns>
        public byte[] GetSharedSecret() => m_shared;
    }
}
