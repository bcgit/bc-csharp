using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>How the secret key material in a secret key packet is protected (RFC 9580 5.5.3).</summary>
    /// <remarks>
    /// Instances are created with the factory methods. They keep a copy of the pass phrase, which the key ring
    /// generator and <see cref="PgpSecretKey.CopyWithNewProtection"/> wipe when they are done with it. A protection
    /// whose pass phrase has been wiped cannot be used again: that throws an <see cref="InvalidOperationException"/>,
    /// so each key ring generator or key copy needs an instance of its own.
    /// </remarks>
    public sealed class PgpSecretKeyProtection
    {
        private static readonly PgpSecretKeyProtection NoProtection = new PgpSecretKeyProtection(
            SecretKeyPacket.UsageNone, SymmetricKeyAlgorithmTag.Null, AeadAlgorithmTag.Eax, null, 0, 0, null);

        /// <summary>No protection: the secret key material is stored in the clear (S2K usage octet 0).</summary>
        public static PgpSecretKeyProtection None => NoProtection;

        /// <summary>
        /// AEAD protection with a key derived by Argon2id (S2K usage octet 253), the recommended protection for
        /// version 6 keys.
        /// </summary>
        /// <param name="cipher">The symmetric cipher; it needs a block size of 128 bits.</param>
        /// <param name="aead">The AEAD mode.</param>
        /// <param name="argon2Template">
        /// The Argon2 parameters. Each protected key gets a fresh salt; the salt of the template is not used.
        /// </param>
        /// <param name="rawPassPhrase">The pass phrase; RFC 9580 recommends UTF-8.</param>
        public static PgpSecretKeyProtection AeadArgon2(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead,
            S2k.Argon2Params argon2Template, byte[] rawPassPhrase)
        {
            CheckAead(cipher, aead);
            if (argon2Template == null)
                throw new ArgumentNullException(nameof(argon2Template));
            if (rawPassPhrase == null)
                throw new ArgumentNullException(nameof(rawPassPhrase));

            return new PgpSecretKeyProtection(SecretKeyPacket.UsageAead, cipher, aead, argon2Template, 0, 0,
                rawPassPhrase);
        }

        /// <summary>
        /// AEAD protection with a key derived by an iterated and salted S2K (S2K usage octet 253).
        /// </summary>
        /// <param name="cipher">The symmetric cipher; it needs a block size of 128 bits.</param>
        /// <param name="aead">The AEAD mode.</param>
        /// <param name="s2kDigest">The hash algorithm of the S2K; MD5, SHA-1 and RIPEMD-160 are not allowed.</param>
        /// <param name="s2kCount">The coded iteration count (0 to 255).</param>
        /// <param name="rawPassPhrase">The pass phrase; RFC 9580 recommends UTF-8.</param>
        public static PgpSecretKeyProtection AeadIterated(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead,
            HashAlgorithmTag s2kDigest, int s2kCount, byte[] rawPassPhrase)
        {
            CheckAead(cipher, aead);
            CheckIterated(s2kDigest, s2kCount, rawPassPhrase);
            if (PgpUtilities.IsWeakS2kHash(s2kDigest))
                throw new ArgumentException("S2K hash not allowed for AEAD protection: " + s2kDigest,
                    nameof(s2kDigest));

            return new PgpSecretKeyProtection(SecretKeyPacket.UsageAead, cipher, aead, null, s2kDigest, s2kCount,
                rawPassPhrase);
        }

        /// <summary>
        /// Protection with CFB encryption and a SHA-1 check (S2K usage octet 254) under a key derived by an iterated
        /// and salted S2K.
        /// </summary>
        /// <param name="cipher">The symmetric cipher; IDEA, TripleDES and CAST5 are not allowed.</param>
        /// <param name="s2kDigest">
        /// The hash algorithm of the S2K; MD5, SHA-1 and RIPEMD-160 are not allowed.
        /// </param>
        /// <param name="s2kCount">The coded iteration count (0 to 255).</param>
        /// <param name="rawPassPhrase">The pass phrase; RFC 9580 recommends UTF-8.</param>
        public static PgpSecretKeyProtection Cfb(SymmetricKeyAlgorithmTag cipher, HashAlgorithmTag s2kDigest,
            int s2kCount, byte[] rawPassPhrase)
        {
            if (cipher == SymmetricKeyAlgorithmTag.Null)
                throw new ArgumentException("no encryption algorithm", nameof(cipher));
            // RFC 9580 9.3: IDEA, TripleDES and CAST5 are only for decryption
            if (PgpUtilities.IsDecryptOnlyCipher(cipher))
                throw new ArgumentException("symmetric algorithm not allowed: " + cipher, nameof(cipher));
            CheckIterated(s2kDigest, s2kCount, rawPassPhrase);
            // RFC 9580 9.5: no S2K with MD5, SHA-1 or RIPEMD-160 in new packets, whatever the key version
            if (PgpUtilities.IsWeakS2kHash(s2kDigest))
                throw new ArgumentException("S2K hash not allowed: " + s2kDigest, nameof(s2kDigest));

            return new PgpSecretKeyProtection(SecretKeyPacket.UsageSha1, cipher, AeadAlgorithmTag.Eax, null, s2kDigest,
                s2kCount, rawPassPhrase);
        }

        private static void CheckAead(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead)
        {
            if (!PgpAead.IsSupportedCipher(cipher))
                throw new ArgumentException("unsupported symmetric algorithm for AEAD: " + cipher, nameof(cipher));
            if (aead != AeadAlgorithmTag.Eax && aead != AeadAlgorithmTag.Ocb && aead != AeadAlgorithmTag.Gcm)
                throw new ArgumentException("unsupported AEAD algorithm: " + aead, nameof(aead));
        }

        private static void CheckIterated(HashAlgorithmTag s2kDigest, int s2kCount, byte[] rawPassPhrase)
        {
            if (s2kCount < 0 || s2kCount > 255)
                throw new ArgumentOutOfRangeException(nameof(s2kCount), "must be in the range 0 to 255");
            if (rawPassPhrase == null)
                throw new ArgumentNullException(nameof(rawPassPhrase));
            // fail early for hash algorithms that are not available
            PgpUtilities.CreateDigest(s2kDigest);
        }

        private readonly int m_usage;
        private readonly SymmetricKeyAlgorithmTag m_cipher;
        private readonly AeadAlgorithmTag m_aead;
        private readonly S2k.Argon2Params m_argon2Template;
        private readonly HashAlgorithmTag m_s2kDigest;
        private readonly int m_s2kCount;
        private readonly byte[] m_passPhrase;
        private bool m_cleared;

        private PgpSecretKeyProtection(int usage, SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead,
            S2k.Argon2Params argon2Template, HashAlgorithmTag s2kDigest, int s2kCount, byte[] rawPassPhrase)
        {
            m_usage = usage;
            m_cipher = cipher;
            m_aead = aead;
            m_argon2Template = argon2Template;
            m_s2kDigest = s2kDigest;
            m_s2kCount = s2kCount;
            m_passPhrase = Arrays.Clone(rawPassPhrase);
        }

        /// <summary>The S2K usage octet.</summary>
        internal int Usage => m_usage;

        internal SymmetricKeyAlgorithmTag Cipher => m_cipher;

        internal AeadAlgorithmTag Aead => m_aead;

        internal S2k.Argon2Params Argon2Template => m_argon2Template;

        internal HashAlgorithmTag S2kDigest => m_s2kDigest;

        internal int S2kCount => m_s2kCount;

        /// <summary>The pass phrase; the protection keeps its own copy, so the caller may wipe the result.</summary>
        /// <exception cref="InvalidOperationException">If the pass phrase has been wiped.</exception>
        internal byte[] GetPassPhrase()
        {
            CheckNotCleared();
            return Arrays.Clone(m_passPhrase);
        }

        /// <summary>
        /// Fail if the pass phrase has been wiped: a wiped pass phrase consists of zeroes, and keys protected with it
        /// would be open to anyone who guesses its length.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the pass phrase has been wiped.</exception>
        internal void CheckNotCleared()
        {
            if (m_cleared)
                throw new InvalidOperationException(
                    "The pass phrase of this protection has been wiped; use a new PgpSecretKeyProtection");
        }

        /// <summary>Wipe the pass phrase held by this object, which cannot be used afterwards.</summary>
        internal void Clear()
        {
            if (m_passPhrase != null)
            {
                Arrays.ZeroMemory(m_passPhrase);
                m_cleared = true;
            }
        }
    }
}
