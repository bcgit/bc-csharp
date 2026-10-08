using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// The session key encryption of the X25519 and X448 algorithms of RFC 9580 (5.1.6, 5.1.7): an ephemeral
    /// Diffie-Hellman key agreement, a key derived from it with HKDF, and AES key wrap of the raw session key.
    /// </summary>
    internal sealed class PgpXdhKem
    {
        /// <summary>The wrapped session key is at least this long (a 128-bit key and the key wrap overhead).</summary>
        private const int MinWrappedKeyLength = 24;

        internal static readonly PgpXdhKem X25519 = new PgpXdhKem(PublicKeyAlgorithmTag.X25519,
            X25519PublicKeyParameters.KeySize, "OpenPGP X25519", kekLength: 16, SymmetricKeyAlgorithmTag.Aes128);

        internal static readonly PgpXdhKem X448 = new PgpXdhKem(PublicKeyAlgorithmTag.X448,
            X448PublicKeyParameters.KeySize, "OpenPGP X448", kekLength: 32, SymmetricKeyAlgorithmTag.Aes256);

        private readonly PublicKeyAlgorithmTag m_algorithm;
        private readonly int m_keyLength;
        private readonly byte[] m_info;
        private readonly int m_kekLength;
        private readonly SymmetricKeyAlgorithmTag m_wrapAlgorithm;

        private PgpXdhKem(PublicKeyAlgorithmTag algorithm, int keyLength, string info, int kekLength,
            SymmetricKeyAlgorithmTag wrapAlgorithm)
        {
            m_algorithm = algorithm;
            m_keyLength = keyLength;
            m_info = Strings.ToUtf8ByteArray(info);
            m_kekLength = kekLength;
            m_wrapAlgorithm = wrapAlgorithm;
        }

        internal static PgpXdhKem ForAlgorithm(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.X25519: return X25519;
            case PublicKeyAlgorithmTag.X448: return X448;
            default: throw new ArgumentException("not an X25519 or X448 key", nameof(algorithm));
            }
        }

        private IDigest CreateDigest() => m_algorithm == PublicKeyAlgorithmTag.X25519
            ? (IDigest)new Sha256Digest()
            : new Sha512Digest();

        /// <summary>The octets of the ephemeral or recipient public key.</summary>
        private static byte[] Encode(AsymmetricKeyParameter publicKey)
        {
            if (publicKey is X25519PublicKeyParameters x25519)
                return x25519.GetEncoded();
            if (publicKey is X448PublicKeyParameters x448)
                return x448.GetEncoded();

            throw new ArgumentException("not an X25519 or X448 public key", nameof(publicKey));
        }

        /// <summary>The encoding of a private key, which the caller has to wipe.</summary>
        private static byte[] EncodePrivateKey(AsymmetricKeyParameter privateKey)
        {
            if (privateKey is X25519PrivateKeyParameters x25519)
                return x25519.GetEncoded();
            if (privateKey is X448PrivateKeyParameters x448)
                return x448.GetEncoded();

            throw new ArgumentException("not an X25519 or X448 private key", nameof(privateKey));
        }

        /// <summary>The shared secret; fails for a public key that results in an all-zero secret.</summary>
        private byte[] CalculateSharedSecret(byte[] privateKey, byte[] peerPublicKey)
        {
            if (peerPublicKey.Length != m_keyLength)
                throw new ArgumentException("invalid public key length", nameof(peerPublicKey));

            byte[] secret = new byte[m_keyLength];

            // RFC 7748 6: the shared secret must not be all zeroes
            bool agreed = m_algorithm == PublicKeyAlgorithmTag.X25519
                ? Math.EC.Rfc7748.X25519.CalculateAgreement(privateKey, 0, peerPublicKey, 0, secret, 0)
                : Math.EC.Rfc7748.X448.CalculateAgreement(privateKey, 0, peerPublicKey, 0, secret, 0);
            if (!agreed)
            {
                Arrays.ZeroMemory(secret);
                throw new PgpException("key agreement failed");
            }

            return secret;
        }

        private byte[] DeriveKek(byte[] ephemeralPublicKey, byte[] recipientPublicKey, byte[] sharedSecret)
        {
            byte[] ikm = Arrays.ConcatenateAll(ephemeralPublicKey, recipientPublicKey, sharedSecret);
            try
            {
                return PgpAead.Hkdf(CreateDigest(), ikm, null, m_info, m_kekLength);
            }
            finally
            {
                Arrays.ZeroMemory(ikm);
            }
        }

        /// <summary>
        /// The algorithm-specific fields of a PKESK packet: the ephemeral public key, the length of the following
        /// fields, the symmetric algorithm (for a version 3 PKESK) and the wrapped session key.
        /// </summary>
        /// <param name="recipient">The recipient's public key.</param>
        /// <param name="sessionKey">The raw session key, without algorithm octet or checksum.</param>
        /// <param name="sessionKeyAlgorithm">
        /// The symmetric algorithm of the session key; it is only written to version 3 PKESK packets.
        /// </param>
        internal byte[] Encrypt(AsymmetricKeyParameter recipient, byte[] sessionKey, bool isVersion3Pkesk,
            SymmetricKeyAlgorithmTag sessionKeyAlgorithm, SecureRandom random)
        {
            // the ephemeral private key only exists in this buffer
            byte[] ephemeralPrivateKey = new byte[m_keyLength];
            try
            {
                if (m_algorithm == PublicKeyAlgorithmTag.X25519)
                {
                    Math.EC.Rfc7748.X25519.GeneratePrivateKey(random, ephemeralPrivateKey);
                }
                else
                {
                    Math.EC.Rfc7748.X448.GeneratePrivateKey(random, ephemeralPrivateKey);
                }

                return Encrypt(recipient, ephemeralPrivateKey, sessionKey, isVersion3Pkesk, sessionKeyAlgorithm,
                    random);
            }
            finally
            {
                Arrays.ZeroMemory(ephemeralPrivateKey);
            }
        }

        /// <summary>As the other overload, with a given ephemeral key pair (for tests with known answers).</summary>
        internal byte[] Encrypt(AsymmetricKeyParameter recipient, AsymmetricCipherKeyPair ephemeral, byte[] sessionKey,
            bool isVersion3Pkesk, SymmetricKeyAlgorithmTag sessionKeyAlgorithm, SecureRandom random)
        {
            byte[] ephemeralPrivateKey = EncodePrivateKey(ephemeral.Private);
            try
            {
                return Encrypt(recipient, ephemeralPrivateKey, sessionKey, isVersion3Pkesk, sessionKeyAlgorithm,
                    random);
            }
            finally
            {
                Arrays.ZeroMemory(ephemeralPrivateKey);
            }
        }

        private byte[] Encrypt(AsymmetricKeyParameter recipient, byte[] ephemeralPrivateKey, byte[] sessionKey,
            bool isVersion3Pkesk, SymmetricKeyAlgorithmTag sessionKeyAlgorithm, SecureRandom random)
        {
            byte[] ephemeralPublicKey = new byte[m_keyLength];
            if (m_algorithm == PublicKeyAlgorithmTag.X25519)
            {
                Math.EC.Rfc7748.X25519.GeneratePublicKey(ephemeralPrivateKey, 0, ephemeralPublicKey, 0);
            }
            else
            {
                Math.EC.Rfc7748.X448.GeneratePublicKey(ephemeralPrivateKey, 0, ephemeralPublicKey, 0);
            }
            byte[] recipientPublicKey = Encode(recipient);

            byte[] sharedSecret = CalculateSharedSecret(ephemeralPrivateKey, recipientPublicKey);
            byte[] kek = null;
            try
            {
                kek = DeriveKek(ephemeralPublicKey, recipientPublicKey, sharedSecret);

                IWrapper wrapper = PgpUtilities.CreateWrapper(m_wrapAlgorithm);
                wrapper.Init(true, new ParametersWithRandom(new KeyParameter(kek), random));
                byte[] wrapped = wrapper.Wrap(sessionKey, 0, sessionKey.Length);

                if (isVersion3Pkesk)
                {
                    return Arrays.ConcatenateAll(ephemeralPublicKey,
                        new byte[]{ (byte)(1 + wrapped.Length), (byte)sessionKeyAlgorithm }, wrapped);
                }

                return Arrays.ConcatenateAll(ephemeralPublicKey, new byte[]{ (byte)wrapped.Length }, wrapped);
            }
            finally
            {
                Arrays.ZeroMemory(sharedSecret);
                if (kek != null)
                {
                    Arrays.ZeroMemory(kek);
                }
            }
        }

        /// <summary>Recover the raw session key from the algorithm-specific fields of a PKESK packet.</summary>
        /// <param name="privateKey">The recipient's private key.</param>
        /// <param name="recipientPublicKey">The recipient's public key material, as in its key packet.</param>
        /// <param name="sessionKeyAlgorithm">
        /// The symmetric algorithm that was written to a version 3 PKESK packet, otherwise
        /// <see cref="SymmetricKeyAlgorithmTag.Null"/>.
        /// </param>
        /// <exception cref="Exception">On any malformed data or failure to unwrap. The callers report these in a
        /// uniform way.</exception>
        internal byte[] Decrypt(AsymmetricKeyParameter privateKey, byte[] recipientPublicKey, byte[] fields,
            bool isVersion3Pkesk, out SymmetricKeyAlgorithmTag sessionKeyAlgorithm)
        {
            // ephemeral public key, length octet, [symmetric algorithm], wrapped session key
            if (fields.Length < m_keyLength + 1)
                throw new InvalidOperationException();

            int length = fields[m_keyLength];
            if (m_keyLength + 1 + length != fields.Length)
                throw new InvalidOperationException();

            int wrappedOffset = m_keyLength + 1;
            sessionKeyAlgorithm = SymmetricKeyAlgorithmTag.Null;
            if (isVersion3Pkesk)
            {
                if (length < 1 + MinWrappedKeyLength)
                    throw new InvalidOperationException();

                sessionKeyAlgorithm = (SymmetricKeyAlgorithmTag)fields[wrappedOffset++];
                if (sessionKeyAlgorithm != SymmetricKeyAlgorithmTag.Aes128 &&
                    sessionKeyAlgorithm != SymmetricKeyAlgorithmTag.Aes192 &&
                    sessionKeyAlgorithm != SymmetricKeyAlgorithmTag.Aes256)
                {
                    throw new InvalidOperationException();
                }
            }
            else if (length < MinWrappedKeyLength)
            {
                throw new InvalidOperationException();
            }

            int wrappedLength = fields.Length - wrappedOffset;
            if ((wrappedLength & 7) != 0)
                throw new InvalidOperationException();

            byte[] ephemeralPublicKey = Arrays.CopyOfRange(fields, 0, m_keyLength);

            byte[] privateKeyEncoding = EncodePrivateKey(privateKey);
            byte[] sharedSecret;
            try
            {
                sharedSecret = CalculateSharedSecret(privateKeyEncoding, ephemeralPublicKey);
            }
            finally
            {
                Arrays.ZeroMemory(privateKeyEncoding);
            }

            byte[] kek = null;
            try
            {
                kek = DeriveKek(ephemeralPublicKey, recipientPublicKey, sharedSecret);

                IWrapper wrapper = PgpUtilities.CreateWrapper(m_wrapAlgorithm);
                wrapper.Init(false, new KeyParameter(kek));
                return wrapper.Unwrap(fields, wrappedOffset, wrappedLength);
            }
            finally
            {
                Arrays.ZeroMemory(sharedSecret);
                if (kek != null)
                {
                    Arrays.ZeroMemory(kek);
                }
            }
        }
    }
}
