using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// The ML-KEM-768+X25519 composite KEM of RFC 9980 (section 4.2): X25519-KEM and ML-KEM-768 run in parallel and
    /// their key shares are combined into the key-encryption key that wraps the session key.
    /// </summary>
    /// <remarks>The implementation is in <see cref="PgpCompositeKem"/>.</remarks>
    internal static class PgpMLKemX25519
    {
        internal const int EcdhCipherTextLength = 32;
        internal const int MLKemCipherTextLength = 1088;

        /// <summary>multiKeyCombine of RFC 9980 4.2.1.</summary>
        internal static byte[] MultiKeyCombine(byte[] mlkemKeyShare, byte[] ecdhKeyShare, byte[] ecdhCipherText,
            byte[] ecdhPublicKey, byte algorithmId)
        {
            return PgpCompositeKem.MultiKeyCombine(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, ecdhPublicKey,
                algorithmId);
        }

        /// <summary>Encapsulate to <paramref name="publicKey"/> and return the key-encryption key.</summary>
        internal static byte[] Encapsulate(MLKem768X25519PublicKeyParameters publicKey, SecureRandom random,
            out byte[] ecdhCipherText, out byte[] mlkemCipherText)
        {
            return PgpCompositeKem.MLKem768X25519.Encapsulate(publicKey.X25519Key, publicKey.MLKemKey, random,
                out ecdhCipherText, out mlkemCipherText);
        }

        /// <summary>Decapsulate with <paramref name="privateKey"/> and return the key-encryption key.</summary>
        /// <exception cref="InvalidOperationException">If the X25519 shared secret is all zeroes.</exception>
        internal static byte[] Decapsulate(MLKem768X25519PrivateKeyParameters privateKey, byte[] ecdhPublicKey,
            byte[] ecdhCipherText, byte[] mlkemCipherText)
        {
            return PgpCompositeKem.MLKem768X25519.Decapsulate(privateKey.X25519Key, privateKey.MLKemKey,
                ecdhPublicKey, ecdhCipherText, mlkemCipherText);
        }
    }
}
