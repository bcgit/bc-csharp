using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    internal sealed class EdDsaSigner
        : ISigner
    {
        private readonly ISigner m_signer;
        private readonly IDigest m_digest;

        internal EdDsaSigner(ISigner signer, IDigest digest)
        {
            m_signer = signer;
            m_digest = digest;
        }

        public string AlgorithmName => m_signer.AlgorithmName;

        public void Init(bool forSigning, ICipherParameters cipherParameters)
        {
            m_signer.Init(forSigning, cipherParameters);
            m_digest.Reset();
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
        }

        private void FinalizeDigest()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int digestSize = m_digest.GetDigestSize();
            Span<byte> hash = digestSize <= 128
                ? stackalloc byte[digestSize]
                : new byte[digestSize];
            m_digest.DoFinal(hash);
            m_signer.BlockUpdate(hash);
#else
            byte[] hash = DigestUtilities.DoFinal(m_digest);
            m_signer.BlockUpdate(hash, 0, hash.Length);
#endif
        }
    }
}
