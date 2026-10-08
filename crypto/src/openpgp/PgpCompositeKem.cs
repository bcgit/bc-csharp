using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// The composite KEMs of RFC 9980 (section 4.2): an ECDH KEM (X25519 or X448) and ML-KEM run in parallel and their
    /// key shares are combined into the key-encryption key that wraps the session key.
    /// </summary>
    internal sealed class PgpCompositeKem
    {
        /// <summary>ML-KEM-768+X25519 (algorithm 35).</summary>
        internal static readonly PgpCompositeKem MLKem768X25519 = new PgpCompositeKem(
            PublicKeyAlgorithmTag.MLKem768_X25519, isX25519: true, ecdhLength: 32, MLKemParameters.ml_kem_768,
            mlKemCipherTextLength: 1088);

        /// <summary>ML-KEM-1024+X448 (algorithm 36).</summary>
        internal static readonly PgpCompositeKem MLKem1024X448 = new PgpCompositeKem(
            PublicKeyAlgorithmTag.MLKem1024_X448, isX25519: false, ecdhLength: 56, MLKemParameters.ml_kem_1024,
            mlKemCipherTextLength: 1568);

        private const int KeyShareLength = 32;

        private static readonly byte[] DomainSeparator = Strings.ToUtf8ByteArray("OpenPGPCompositeKDFv1");

        private readonly PublicKeyAlgorithmTag m_algorithm;
        private readonly bool m_isX25519;
        private readonly int m_ecdhLength;
        private readonly MLKemParameters m_mlKemParameters;
        private readonly int m_mlKemCipherTextLength;

        private PgpCompositeKem(PublicKeyAlgorithmTag algorithm, bool isX25519, int ecdhLength,
            MLKemParameters mlKemParameters, int mlKemCipherTextLength)
        {
            m_algorithm = algorithm;
            m_isX25519 = isX25519;
            m_ecdhLength = ecdhLength;
            m_mlKemParameters = mlKemParameters;
            m_mlKemCipherTextLength = mlKemCipherTextLength;
        }

        internal static PgpCompositeKem ForAlgorithm(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.MLKem768_X25519: return MLKem768X25519;
            case PublicKeyAlgorithmTag.MLKem1024_X448: return MLKem1024X448;
            default: throw new ArgumentException("not a composite KEM algorithm", nameof(algorithm));
            }
        }

        /// <summary>The length of the ECDH ciphertext (the ephemeral public key) in octets.</summary>
        internal int EcdhCipherTextLength => m_ecdhLength;

        /// <summary>The length of the ML-KEM ciphertext in octets.</summary>
        internal int MLKemCipherTextLength => m_mlKemCipherTextLength;

        /// <summary>multiKeyCombine of RFC 9980 4.2.1.</summary>
        internal byte[] MultiKeyCombine(byte[] mlkemKeyShare, byte[] ecdhKeyShare, byte[] ecdhCipherText,
            byte[] ecdhPublicKey) => MultiKeyCombine(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, ecdhPublicKey,
                (byte)m_algorithm);

        /// <summary>multiKeyCombine of RFC 9980 4.2.1, with an explicit algorithm ID.</summary>
        internal static byte[] MultiKeyCombine(byte[] mlkemKeyShare, byte[] ecdhKeyShare, byte[] ecdhCipherText,
            byte[] ecdhPublicKey, byte algorithmId)
        {
            var digest = new Sha3Digest(256);
            digest.BlockUpdate(mlkemKeyShare, 0, mlkemKeyShare.Length);
            digest.BlockUpdate(ecdhKeyShare, 0, ecdhKeyShare.Length);
            digest.BlockUpdate(ecdhCipherText, 0, ecdhCipherText.Length);
            digest.BlockUpdate(ecdhPublicKey, 0, ecdhPublicKey.Length);
            digest.Update(algorithmId);
            digest.BlockUpdate(DomainSeparator, 0, DomainSeparator.Length);
            digest.Update((byte)DomainSeparator.Length);

            byte[] kek = new byte[digest.GetDigestSize()];
            digest.DoFinal(kek, 0);
            return kek;
        }

        /// <summary>Encapsulate to the public keys and return the key-encryption key.</summary>
        /// <param name="ecdhPublicKey">An <see cref="X25519PublicKeyParameters"/> or X448 public key.</param>
        internal byte[] Encapsulate(AsymmetricKeyParameter ecdhPublicKey, MLKemPublicKeyParameters mlKemPublicKey,
            SecureRandom random, out byte[] ecdhCipherText, out byte[] mlkemCipherText)
        {
            byte[] ecdhKeyShare = new byte[m_ecdhLength];
            byte[] mlkemKeyShare = new byte[KeyShareLength];

            // the ephemeral ECDH private key only exists in this buffer
            byte[] ephemeralPrivateKey = new byte[m_ecdhLength];
            try
            {
                byte[] recipientEncoding;
                ecdhCipherText = new byte[m_ecdhLength];
                bool agreed;
                if (m_isX25519)
                {
                    recipientEncoding = ((X25519PublicKeyParameters)ecdhPublicKey).GetEncoded();
                    X25519.GeneratePrivateKey(random, ephemeralPrivateKey);
                    X25519.GeneratePublicKey(ephemeralPrivateKey, 0, ecdhCipherText, 0);
                    agreed = X25519.CalculateAgreement(ephemeralPrivateKey, 0, recipientEncoding, 0, ecdhKeyShare, 0);
                }
                else
                {
                    recipientEncoding = ((X448PublicKeyParameters)ecdhPublicKey).GetEncoded();
                    X448.GeneratePrivateKey(random, ephemeralPrivateKey);
                    X448.GeneratePublicKey(ephemeralPrivateKey, 0, ecdhCipherText, 0);
                    agreed = X448.CalculateAgreement(ephemeralPrivateKey, 0, recipientEncoding, 0, ecdhKeyShare, 0);
                }

                // RFC 9980 3.4: the shared secret of a point of low order is all zeroes
                if (!agreed)
                    throw new PgpException((m_isX25519 ? "X25519" : "X448") + " key agreement failed");

                var encapsulator = new MLKemEncapsulator(m_mlKemParameters);
                encapsulator.Init(new ParametersWithRandom(mlKemPublicKey, random));
                mlkemCipherText = new byte[encapsulator.EncapsulationLength];
                encapsulator.Encapsulate(mlkemCipherText, 0, mlkemCipherText.Length, mlkemKeyShare, 0,
                    mlkemKeyShare.Length);

                return MultiKeyCombine(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, recipientEncoding);
            }
            finally
            {
                Arrays.ZeroMemory(ephemeralPrivateKey);
                Arrays.ZeroMemory(ecdhKeyShare);
                Arrays.ZeroMemory(mlkemKeyShare);
            }
        }

        /// <summary>Decapsulate with the private keys and return the key-encryption key.</summary>
        /// <param name="ecdhPrivateKey">An <see cref="X25519PrivateKeyParameters"/> or X448 private key.</param>
        /// <param name="ecdhPublicKey">The encoding of the recipient's ECDH public key, from its key packet.</param>
        /// <exception cref="InvalidOperationException">If the ECDH shared secret is all zeroes.</exception>
        internal byte[] Decapsulate(AsymmetricKeyParameter ecdhPrivateKey, MLKemPrivateKeyParameters mlKemPrivateKey,
            byte[] ecdhPublicKey, byte[] ecdhCipherText, byte[] mlkemCipherText)
        {
            byte[] ecdhKeyShare = new byte[m_ecdhLength];
            byte[] mlkemKeyShare = new byte[KeyShareLength];
            try
            {
                if (m_isX25519)
                {
                    ((X25519PrivateKeyParameters)ecdhPrivateKey).GenerateSecret(
                        new X25519PublicKeyParameters(ecdhCipherText), ecdhKeyShare, 0);
                }
                else
                {
                    ((X448PrivateKeyParameters)ecdhPrivateKey).GenerateSecret(
                        new X448PublicKeyParameters(ecdhCipherText), ecdhKeyShare, 0);
                }

                var decapsulator = new MLKemDecapsulator(m_mlKemParameters);
                decapsulator.Init(mlKemPrivateKey);
                decapsulator.Decapsulate(mlkemCipherText, 0, mlkemCipherText.Length, mlkemKeyShare, 0,
                    mlkemKeyShare.Length);

                return MultiKeyCombine(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, ecdhPublicKey);
            }
            finally
            {
                Arrays.ZeroMemory(ecdhKeyShare);
                Arrays.ZeroMemory(mlkemKeyShare);
            }
        }
    }
}
