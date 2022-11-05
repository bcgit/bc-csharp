using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    internal sealed class EdDsaSigner
        : ISigner
    {
        private readonly ISigner m_signer;
        private readonly IDigest m_digest;
        private readonly byte[] m_digBuf;

        internal EdDsaSigner(ISigner signer, IDigest digest)
        {
            m_signer = signer;
            m_digest = digest;
            m_digBuf = new byte[digest.GetDigestSize()];
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

        public byte[] GenerateSignature()
        {
            m_digest.DoFinal(m_digBuf, 0);

            m_signer.BlockUpdate(m_digBuf, 0, m_digBuf.Length);

            return m_signer.GenerateSignature();
        }

        public bool VerifySignature(byte[] signature)
        {
            m_digest.DoFinal(m_digBuf, 0);

            m_signer.BlockUpdate(m_digBuf, 0, m_digBuf.Length);

            return m_signer.VerifySignature(signature);
        }

        public void Reset()
        {
            Arrays.Clear(m_digBuf);
            m_signer.Reset();
            m_digest.Reset();
        }
    }
}
