using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    public sealed class MLDsaSigner
        : ISigner
    {
        private readonly byte[] m_ctx;
        private readonly bool m_deterministic;

        private readonly ShakeDigest m_msgRepDigest = DilithiumEngine.MsgRepCreateDigest();

        private MLDsaPrivateKeyParameters m_privateKey;
        private MLDsaPublicKeyParameters m_publicKey;
        private DilithiumEngine m_engine;

        public MLDsaSigner()
        {
            m_ctx = Array.Empty<byte>();
            m_deterministic = false;
        }

        public MLDsaSigner(byte[] ctx, bool deterministic)
        {
            if (ctx == null)
                throw new ArgumentNullException(nameof(ctx));
            if (ctx.Length > 255)
                throw new ArgumentOutOfRangeException(nameof(ctx));

            m_ctx = (byte[])ctx.Clone();
            m_deterministic = deterministic;
        }

        public string AlgorithmName => "ML-DSA";

        public void Init(bool forSigning, ICipherParameters parameters)
        {
            if (forSigning)
            {
                SecureRandom providedRandom = null;
                if (parameters is ParametersWithRandom withRandom)
                {
                    providedRandom = withRandom.Random;
                    parameters = withRandom.Parameters;
                }

                m_privateKey = (MLDsaPrivateKeyParameters)parameters;
                m_publicKey = null;

                var random = m_deterministic ? null : CryptoServicesRegistrar.GetSecureRandom(providedRandom);
                m_engine = m_privateKey.Parameters.GetEngine(random);
            }
            else
            {
                m_privateKey = null;
                m_publicKey = (MLDsaPublicKeyParameters)parameters;

                m_engine = m_publicKey.Parameters.GetEngine(random: null);
            }

            Reset();
        }

        public void Update(byte b)
        {
            m_msgRepDigest.Update(b);
        }

        public void BlockUpdate(byte[] buf, int off, int len)
        {
            m_msgRepDigest.BlockUpdate(buf, off, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            m_msgRepDigest.BlockUpdate(input);
        }
#endif

        public int GetMaxSignatureSize() => m_engine.CryptoBytes;

        public byte[] GenerateSignature()
        {
            if (m_privateKey == null)
                throw new InvalidOperationException("MLDsaSigner not initialised for signature generation.");

            byte[] sig = new byte[m_engine.CryptoBytes];
            m_engine.MsgRepEndSign(m_msgRepDigest, sig, sig.Length, m_privateKey.m_rho, m_privateKey.m_k,
                m_privateKey.m_t0, m_privateKey.m_s1, m_privateKey.m_s2);

            Reset();
            return sig;
        }

        public bool VerifySignature(byte[] signature)
        {
            if (m_publicKey == null)
                throw new InvalidOperationException("MLDsaSigner not initialised for verification");

            bool result = m_engine.MsgRepEndVerify(m_msgRepDigest, signature, signature.Length, m_publicKey.m_rho,
                encT1: m_publicKey.m_t1);

            Reset();
            return result;
        }

        public void Reset()
        {
            m_msgRepDigest.Reset();

            byte[] tr = m_privateKey != null ? m_privateKey.m_tr : m_publicKey.GetPublicKeyHash();
            m_engine.MsgRepBegin(m_msgRepDigest, tr);

            // TODO Prehash variant uses 0x01 here
            m_msgRepDigest.Update(0x00);
            m_msgRepDigest.Update((byte)m_ctx.Length);
            m_msgRepDigest.BlockUpdate(m_ctx, 0, m_ctx.Length);
        }
    }
}
