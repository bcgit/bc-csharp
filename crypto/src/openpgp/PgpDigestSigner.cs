using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// A signer for the algorithms of OpenPGP that sign a digest of the data rather than the data itself (RFC 9580
    /// 5.2.4): the data is hashed with the hash algorithm of the signature, and the digest is what the wrapped signer
    /// signs.
    /// </summary>
    internal sealed class PgpDigestSigner
        : ISigner
    {
        private readonly ISigner m_signer;
        private readonly IDigest m_digest;
        private readonly bool m_ignoreRandom;

        private byte[] m_lastDigest;

        internal PgpDigestSigner(ISigner signer, IDigest digest)
        {
            m_signer = signer;
            m_digest = digest;

            // Ed25519 and Ed448 are deterministic and do not accept a SecureRandom
            m_ignoreRandom = signer is Ed25519Signer || signer is Ed448Signer;
        }

        public string AlgorithmName => m_signer.AlgorithmName;

        /// <summary>The digest that was signed or verified by the last operation.</summary>
        internal byte[] LastDigest => m_lastDigest;

        public void Init(bool forSigning, ICipherParameters cipherParameters)
        {
            if (m_ignoreRandom)
            {
                cipherParameters = ParameterUtilities.IgnoreRandom(cipherParameters);
            }

            m_signer.Init(forSigning, cipherParameters);
            m_digest.Reset();
            m_lastDigest = null;
        }

        public void Update(byte b)
        {
            m_digest.Update(b);
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            m_digest.BlockUpdate(input, inOff, inLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            m_digest.BlockUpdate(input);
        }
#endif

        public int GetMaxSignatureSize() => m_signer.GetMaxSignatureSize();

        public byte[] GenerateSignature()
        {
            FinalizeDigest();
            return m_signer.GenerateSignature();
        }

        public bool VerifySignature(byte[] signature)
        {
            FinalizeDigest();
            return m_signer.VerifySignature(signature);
        }

        public void Reset()
        {
            m_signer.Reset();
            m_digest.Reset();
            m_lastDigest = null;
        }

        private void FinalizeDigest()
        {
            byte[] hash = DigestUtilities.DoFinal(m_digest);
            m_lastDigest = hash;
            m_signer.BlockUpdate(hash, 0, hash.Length);
        }
    }
}
