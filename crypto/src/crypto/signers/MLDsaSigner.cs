using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers.MLDsa;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    public sealed class MLDsaSigner
        : ISigner
    {
        private readonly ShakeDigest m_msgRepDigest = MLDsaEngine.MsgRepCreateDigest();

        private readonly MLDsaParameters m_parameters;
        private readonly bool m_deterministic;

        private byte[] m_context;
        private MLDsaPrivateKeyParameters m_privateKey;
        private MLDsaPublicKeyParameters m_publicKey;
        private MLDsaEngine m_engine;

        public MLDsaSigner(MLDsaParameters parameters, bool deterministic)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (parameters.PreHashOid != null)
                throw new ArgumentException("cannot be used for HashML-DSA", nameof(parameters));

            m_parameters = parameters;
            m_deterministic = deterministic;
        }

        public string AlgorithmName => m_parameters.Name;

        public void Init(bool forSigning, ICipherParameters parameters)
        {
            parameters = ParameterUtilities.GetContext(parameters, minLen: 0, maxLen: 255, out var providedContext);

            m_context = providedContext ?? Array.Empty<byte>();

            if (forSigning)
            {
                parameters = ParameterUtilities.GetRandom(parameters, out var providedRandom);

                m_privateKey = (MLDsaPrivateKeyParameters)parameters;
                m_publicKey = null;

                var random = m_deterministic ? null : CryptoServicesRegistrar.GetSecureRandom(providedRandom);
                m_engine = GetEngine(m_privateKey.Parameters, random);
            }
            else
            {
                m_privateKey = null;
                m_publicKey = (MLDsaPublicKeyParameters)parameters;

                m_engine = GetEngine(m_publicKey.Parameters, random: null);
            }

            Reset();
        }

        public void Update(byte input) => m_msgRepDigest.Update(input);

        public void BlockUpdate(byte[] input, int inOff, int inLen) => m_msgRepDigest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input) => m_msgRepDigest.BlockUpdate(input);
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

            bool result = m_engine.MsgRepEndVerifyInternal(m_msgRepDigest, signature, signature.Length,
                m_publicKey.m_rho, encT1: m_publicKey.m_t1);

            Reset();
            return result;
        }

        public void Reset()
        {
            m_msgRepDigest.Reset();

            byte[] tr = m_privateKey != null ? m_privateKey.m_tr : m_publicKey.GetPublicKeyHash();
            m_engine.MsgRepBegin(m_msgRepDigest, tr);

            m_msgRepDigest.Update(0x00);
            m_msgRepDigest.Update((byte)m_context.Length);
            m_msgRepDigest.BlockUpdate(m_context, 0, m_context.Length);
        }

        private MLDsaEngine GetEngine(MLDsaParameters keyParameters, SecureRandom random)
        {
            var keyParameterSet = keyParameters.ParameterSet;

            if (keyParameterSet != m_parameters.ParameterSet)
                throw new ArgumentException("Mismatching key parameter set", nameof(keyParameters));

            return keyParameterSet.GetEngine(random);
        }
    }
}
