using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Tls
{
    /// <summary>
    /// Support for RSA key exchange in TLS, including the countermeasures against attacks on PKCS#1 v1.5 padding.
    /// </summary>
    public static class TlsRsaKeyExchange
    {
        /// <summary>The <c>PreMasterSecretLength</c> constant, with the value <c>48</c>.</summary>
        public const int PreMasterSecretLength = 48;

        /// <summary>
        /// Decrypt a TLS pre-master secret, using countermeasures against padding oracle attacks: if the encrypted
        /// value is invalid, a random value is returned instead.
        /// </summary>
        /// <param name="buf">The buffer holding the encrypted pre-master secret.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which the encrypted value starts.</param>
        /// <param name="len">The length of the encrypted value.</param>
        /// <param name="privateKey">The RSA private key.</param>
        /// <param name="protocolVersion">
        /// The protocol version, as a 16-bit value, that the pre-master secret is expected to carry.
        /// </param>
        /// <param name="secureRandom">The source of randomness for the fallback value.</param>
        /// <returns>The pre-master secret.</returns>
        /// <exception cref="ArgumentException"><paramref name="protocolVersion"/> is not a 16-bit value.</exception>
        public static byte[] DecryptPreMasterSecret(byte[] buf, int off, int len, RsaKeyParameters privateKey,
            int protocolVersion, SecureRandom secureRandom)
        {
            if ((protocolVersion & 0xFFFF) != protocolVersion)
                throw new ArgumentException("must be a 16 bit value", nameof(protocolVersion));

            RsaPkcs1Utilities.ValidityCheck protocolVersionCheck = (_buf, _off, _len) =>
                Pack.BE_To_UInt16(_buf, _off) ^ protocolVersion;

            return RsaPkcs1Utilities.DecryptToFixedLength(PreMasterSecretLength, buf, off, len, privateKey,
                secureRandom, protocolVersionCheck);
        }

        /// <summary>Get the maximum length of the encrypted value that can be decrypted with the given key.</summary>
        /// <param name="privateKey">The RSA private key.</param>
        /// <returns>The maximum length in bytes.</returns>
        public static int GetInputLimit(RsaKeyParameters privateKey) => RsaPkcs1Utilities.GetInputLimit(privateKey);
    }
}
