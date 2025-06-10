using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    public sealed class HashSlhDsaSigner
        : ISigner
    {
        private readonly Buffer m_buffer = new Buffer();
        private readonly SlhDsaParameters m_parameters;
        private readonly byte[] m_preHashOidEncoding;
        private readonly IDigest m_preHashDigest;
        private readonly bool m_deterministic;

        private SlhDsaPrivateKeyParameters m_privateKey;
        private SlhDsaPublicKeyParameters m_publicKey;
        private SecureRandom m_random;
        private SphincsPlusEngine m_engine;

        public HashSlhDsaSigner(SlhDsaParameters parameters, bool deterministic)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (parameters.PreHashOid == null)
                throw new ArgumentException("cannot be used for SLH-DSA", nameof(parameters));

            m_parameters = parameters;
            m_preHashOidEncoding = parameters.PreHashOid.GetEncoded(Asn1Encodable.Der);
            m_preHashDigest = DigestUtilities.GetDigest(parameters.PreHashOid);
            m_deterministic = deterministic;
        }

        public string AlgorithmName => m_parameters.Name;

        public void Init(bool forSigning, ICipherParameters parameters)
        {
            byte[] providedContext = null;
            if (parameters is ParametersWithContext withContext)
            {
                if (withContext.ContextLength > 255)
                    throw new ArgumentOutOfRangeException("context too long", nameof(parameters));

                providedContext = withContext.GetContext();
                parameters = withContext.Parameters;
            }

            if (forSigning)
            {
                parameters = ParameterUtilities.GetRandom(parameters, out var providedRandom);

                m_privateKey = (SlhDsaPrivateKeyParameters)parameters;
                m_publicKey = null;

                m_random = m_deterministic ? null : CryptoServicesRegistrar.GetSecureRandom(providedRandom);
                m_engine = GetEngine(m_privateKey.Parameters);
            }
            else
            {
                m_privateKey = null;
                m_publicKey = (SlhDsaPublicKeyParameters)parameters;

                m_random = null;
                m_engine = GetEngine(m_publicKey.Parameters);
            }

            m_buffer.Init(context: providedContext ?? Array.Empty<byte>(), m_preHashOidEncoding);
        }

        public void Update(byte input) => m_preHashDigest.Update(input);

        public void BlockUpdate(byte[] input, int inOff, int inLen) => m_preHashDigest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input) => m_preHashDigest.BlockUpdate(input);
#endif

        public int GetMaxSignatureSize() => m_engine.SignatureLength;

        public byte[] GenerateSignature()
        {
            if (m_privateKey == null)
                throw new InvalidOperationException("HashSlhDsaSigner not initialised for signature generation.");

            FinishPreHash();

            return m_buffer.GenerateSignature(m_privateKey, m_engine, m_random);
        }

        public bool VerifySignature(byte[] signature)
        {
            if (m_publicKey == null)
                throw new InvalidOperationException("HashSlhDsaSigner not initialised for verification");

            FinishPreHash();

            return m_buffer.VerifySignature(m_publicKey, m_engine, signature);
        }

        public void Reset() => m_preHashDigest.Reset();

        private void FinishPreHash()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> preHash = stackalloc byte[m_preHashDigest.GetDigestSize()];
            m_preHashDigest.DoFinal(preHash);
            m_buffer.Write(preHash);
#else
            byte[] preHash = DigestUtilities.DoFinal(m_preHashDigest);
            m_buffer.Write(preHash, 0, preHash.Length);
#endif
        }

        private SphincsPlusEngine GetEngine(SlhDsaParameters keyParameters)
        {
            var keyParameterSet = keyParameters.ParameterSet;

            if (keyParameterSet != m_parameters.ParameterSet)
                throw new ArgumentException("Mismatching key parameter set", nameof(keyParameters));

            return keyParameterSet.GetEngine();
        }

        private sealed class Buffer : MemoryStream
        {
            private int m_prefixLength;

            internal void Init(byte[] context, byte[] preHashOidEncoding)
            {
                lock (this)
                {
                    TruncateAndClear(newLength: 0);

                    WriteByte(0x01);
                    WriteByte((byte)context.Length);
                    Write(context, 0, context.Length);
                    Write(preHashOidEncoding, 0, preHashOidEncoding.Length);

                    m_prefixLength = Convert.ToInt32(Length);
                }
            }

            internal byte[] GenerateSignature(SlhDsaPrivateKeyParameters privateKey, SphincsPlusEngine engine,
                SecureRandom random)
            {
                lock (this)
                {
                    byte[] buf = GetBuffer();
                    int count = Convert.ToInt32(Length);

                    byte[] addrnd = random == null ? null : SecureRandom.GetNextBytes(random, engine.N);

                    byte[] signature = privateKey.SignInternal(optRand: addrnd, buf, 0, count);
                    Reset();
                    return signature;
                }
            }

            internal bool VerifySignature(SlhDsaPublicKeyParameters publicKey, SphincsPlusEngine engine,
                byte[] signature)
            {
                if (engine.SignatureLength != signature.Length)
                {
                    Reset();
                    return false;
                }

                lock (this)
                {
                    byte[] buf = GetBuffer();
                    int count = Convert.ToInt32(Length);

                    bool result = publicKey.VerifyInternal(buf, 0, count, signature);
                    Reset();
                    return result;
                }
            }

            internal void Reset()
            {
                lock (this) TruncateAndClear(newLength: m_prefixLength);
            }

            private void TruncateAndClear(int newLength)
            {
                int count = Convert.ToInt32(Length);
                Array.Clear(GetBuffer(), newLength, count - newLength);
                SetLength(newLength);
            }
        }
    }
}
