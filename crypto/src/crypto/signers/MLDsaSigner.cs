using System;
using System.IO;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    public sealed class MLDsaSigner
        : ISigner
    {
        private readonly Buffer m_buffer;
        private readonly bool m_deterministic;

        private bool m_forSigning;
        private MLDsaPrivateKeyParameters m_privateKey;
        private MLDsaPublicKeyParameters m_publicKey;   
        private DilithiumEngine m_engine;

        public MLDsaSigner()
        {
            m_buffer = new Buffer(Array.Empty<byte>());
            m_deterministic = false;
        }

        public MLDsaSigner(byte[] ctx, bool deterministic)
        {
            if (ctx == null)
                throw new ArgumentNullException(nameof(ctx));
            if (ctx.Length > 255)
                throw new ArgumentOutOfRangeException(nameof(ctx));

            m_buffer = new Buffer((byte[])ctx.Clone());
            m_deterministic = deterministic;
        }

        public string AlgorithmName => "ML-DSA";

        public void Init(bool forSigning, ICipherParameters parameters)
        {
            m_forSigning = forSigning;

            SecureRandom random = null;
            if (parameters is ParametersWithRandom withRandom)
            {
                random = withRandom.Random;
                parameters = withRandom.Parameters;
            }

            if (forSigning)
            {
                m_privateKey = (MLDsaPrivateKeyParameters)parameters;
                m_publicKey = null;

                m_engine = m_privateKey.Parameters.GetEngine(random);
            }
            else
            {
                m_privateKey = null;
                m_publicKey = (MLDsaPublicKeyParameters)parameters;

                m_engine = m_publicKey.Parameters.GetEngine(null);
            }

            Reset();
        }

        public void Update(byte b)
        {
            m_buffer.WriteByte(b);
        }

        public void BlockUpdate(byte[] buf, int off, int len)
        {
            m_buffer.Write(buf, off, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            m_buffer.Write(input);
        }
#endif

        public int GetMaxSignatureSize() => m_engine.CryptoBytes;

        public byte[] GenerateSignature()
        {
            if (!m_forSigning || null == m_privateKey)
                throw new InvalidOperationException("MLDsaSigner not initialised for signature generation.");

            return m_buffer.GenerateSignature(m_privateKey, m_engine);
        }

        public bool VerifySignature(byte[] signature)
        {
            if (m_forSigning || null == m_publicKey)
                throw new InvalidOperationException("MLDsaSigner not initialised for verification");

            return m_buffer.VerifySignature(m_publicKey, m_engine, signature);
        }

        public void Reset()
        {
            m_buffer.Reset();
        }

        private sealed class Buffer : MemoryStream
        {
            private readonly int m_prefixLength;

            internal Buffer(byte[] ctx)
            {
                // TODO Prehash variant uses 0x01 here
                WriteByte(0x00);
                WriteByte((byte)ctx.Length);
                Write(ctx, 0, ctx.Length);

                m_prefixLength = 2 + ctx.Length;
            }

            internal byte[] GenerateSignature(MLDsaPrivateKeyParameters privateKey, DilithiumEngine engine)
            {
                lock (this)
                {
                    byte[] buf = GetBuffer();
                    int count = Convert.ToInt32(Length);

                    byte[] sig = new byte[engine.CryptoBytes];
                    engine.Sign(sig, sig.Length, buf, 0, count, privateKey.m_rho, privateKey.m_k, privateKey.m_tr,
                        privateKey.m_t0, privateKey.m_s1, privateKey.m_s2);
                    return sig;
                }
            }

            internal bool VerifySignature(MLDsaPublicKeyParameters publicKey, DilithiumEngine engine, byte[] signature)
            {
                if (engine.CryptoBytes != signature.Length)
                {
                    Reset();
                    return false;
                }

                lock (this)
                {
                    byte[] buf = GetBuffer();
                    int count = Convert.ToInt32(Length);

                    bool result = engine.Verify(signature, signature.Length, buf, 0, count, publicKey.m_rho,
                        encT1: publicKey.m_t1);
                    Reset();
                    return result;
                }
            }

            internal void Reset()
            {
                lock (this)
                {
                    int count = Convert.ToInt32(Length);
                    Array.Clear(GetBuffer(), m_prefixLength, count - m_prefixLength);
                    SetLength(m_prefixLength);
                }
            }
        }
    }
}
