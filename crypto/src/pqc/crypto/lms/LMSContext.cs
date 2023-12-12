using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsContext
        : IDigest
    {
        private readonly byte[] m_c;
        private readonly LMOtsPrivateKey m_privateKey;
        private readonly LMSigParameters m_sigParams;
        private readonly byte[][] m_path;

        private readonly LMOtsPublicKey m_publicKey;
        private readonly object m_signature;
        private LmsSignedPubKey[] m_signedPubKeys;
        private volatile IDigest m_digest;

        // TODO[api] Make internal
        public LmsContext(LMOtsPrivateKey privateKey, LMSigParameters sigParams, IDigest digest, byte[] C,
            byte[][] path)
        {
            m_privateKey = privateKey;
            m_sigParams = sigParams;
            m_digest = digest;
            m_c = C;
            m_path = path;
            m_publicKey = null;
            m_signature = null;
        }

        // TODO[api] Make internal
        public LmsContext(LMOtsPublicKey publicKey, object signature, IDigest digest)
        {
            m_publicKey = publicKey;
            m_signature = signature;
            m_digest = digest;
            m_c = null;
            m_privateKey = null;
            m_sigParams = null;
            m_path = null;
        }

        public byte[] C => m_c;

        public byte[] GetQ()
        {
            byte[] Q = new byte[LMOts.MAX_HASH + 2];
            m_digest.DoFinal(Q, 0);
            m_digest = null;
            return Q;
        }

        internal byte[][] Path => m_path;

        internal LMOtsPrivateKey PrivateKey => m_privateKey;

        // TODO[api] Make internal
        public LMOtsPublicKey PublicKey => m_publicKey;

        internal LMSigParameters SigParams => m_sigParams;

        public object Signature => m_signature;

        internal LmsSignedPubKey[] SignedPubKeys => m_signedPubKeys;

        internal LmsContext WithSignedPublicKeys(LmsSignedPubKey[] signedPubKeys)
        {
            m_signedPubKeys = signedPubKeys;
            return this;
        }

        public string AlgorithmName => m_digest.AlgorithmName;

        public int GetDigestSize() => m_digest.GetDigestSize();

        public int GetByteLength() => m_digest.GetByteLength();

        public void Update(byte input)
        {
            m_digest.Update(input);
        }

        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            m_digest.BlockUpdate(input, inOff, len);
        }

        public int DoFinal(byte[] output, int outOff)
        {
            return m_digest.DoFinal(output, outOff);
        }

        public void Reset()
        {
            m_digest.Reset();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            m_digest.BlockUpdate(input);
        }

        public int DoFinal(Span<byte> output)
        {
            return m_digest.DoFinal(output);
        }
#endif
    }
}
