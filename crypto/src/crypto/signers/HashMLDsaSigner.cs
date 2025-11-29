using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers.MLDsa;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    public sealed class HashMLDsaSigner
        : ISigner
    {
        private readonly ShakeDigest m_msgRepDigest = MLDsaEngine.MsgRepCreateDigest();

        private readonly MLDsaParameters m_parameters;
        private readonly byte[] m_preHashOidEncoding;
        private readonly IDigest m_preHashDigest;
        private readonly bool m_deterministic;

        private byte[] m_context;
        private MLDsaPrivateKeyParameters m_privateKey;
        private MLDsaPublicKeyParameters m_publicKey;
        private MLDsaEngine m_engine;

        public HashMLDsaSigner(MLDsaParameters parameters, bool deterministic)
            : this(parameters, deterministic,
                  DigestUtilities.GetDigest(parameters.PreHashOid),
                  parameters.PreHashOid)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (parameters.PreHashOid == null)
                throw new ArgumentException("cannot be used for ML-DSA", nameof(parameters));
        }

        public static HashMLDsaSigner CreatePrehashSigner(MLDsaParameters parameters, bool deterministic)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (parameters.PreHashOid == null)
                throw new ArgumentException("cannot be used for ML-DSA", nameof(parameters));

            IDigest preHashDigest =  DigestUtilities.GetDigest(parameters.PreHashOid);
            return new HashMLDsaSigner(parameters, deterministic, Prehash.ForDigest(preHashDigest), parameters.PreHashOid);
        }

        public static HashMLDsaSigner CreatePrehashSigner(MLDsaParameters parametersWithoutPrehash, bool deterministic, DerObjectIdentifier preHashOid)
        {
            if (parametersWithoutPrehash == null)
                throw new ArgumentNullException(nameof(parametersWithoutPrehash));
            if (preHashOid == null)
                throw new ArgumentNullException(nameof(preHashOid));

            IDigest preHashDigest = DigestUtilities.GetDigest(preHashOid);
            return new HashMLDsaSigner(parametersWithoutPrehash, deterministic, Prehash.ForDigest(preHashDigest), preHashOid);
        }

        private HashMLDsaSigner(MLDsaParameters parameters, bool deterministic, IDigest preHashDigest, DerObjectIdentifier preHashOid)
        {
            m_parameters = parameters;
            m_preHashOidEncoding = preHashOid.GetEncoded(Asn1Encodable.Der);
            m_preHashDigest = preHashDigest;
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

            // Cache the prefix
            {
                m_msgRepDigest.Reset();

                byte[] tr = m_privateKey != null ? m_privateKey.m_tr : m_publicKey.GetPublicKeyHash();
                m_engine.MsgRepBegin(m_msgRepDigest, tr);

                m_msgRepDigest.Update(0x01);
                m_msgRepDigest.Update((byte)m_context.Length);
                m_msgRepDigest.BlockUpdate(m_context, 0, m_context.Length);
                m_msgRepDigest.BlockUpdate(m_preHashOidEncoding, 0, m_preHashOidEncoding.Length);
            }

            Reset();
        }

        public void Update(byte input) => m_preHashDigest.Update(input);

        public void BlockUpdate(byte[] input, int inOff, int inLen) => m_preHashDigest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input) => m_preHashDigest.BlockUpdate(input);
#endif

        public int GetMaxSignatureSize() => m_engine.CryptoBytes;

        public byte[] GenerateSignature()
        {
            if (m_privateKey == null)
                throw new InvalidOperationException("HashMLDsaSigner not initialised for signature generation.");

            ShakeDigest msgRepDigest = FinishPreHash();

            byte[] sig = new byte[m_engine.CryptoBytes];
            m_engine.MsgRepEndSign(msgRepDigest, sig, sig.Length, m_privateKey.m_rho, m_privateKey.m_k,
                m_privateKey.m_t0, m_privateKey.m_s1, m_privateKey.m_s2);
            return sig;
        }

        public bool VerifySignature(byte[] signature)
        {
            if (m_publicKey == null)
                throw new InvalidOperationException("HashMLDsaSigner not initialised for verification");

            ShakeDigest msgRepDigest = FinishPreHash();

            return m_engine.MsgRepEndVerifyInternal(msgRepDigest, signature, signature.Length, m_publicKey.m_rho,
                encT1: m_publicKey.m_t1);
        }

        public void Reset() => m_preHashDigest.Reset();

        private ShakeDigest FinishPreHash()
        {
            ShakeDigest msgRepDigest = new ShakeDigest(m_msgRepDigest);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> preHash = stackalloc byte[msgRepDigest.GetDigestSize()];
            m_preHashDigest.DoFinal(preHash);
            msgRepDigest.BlockUpdate(preHash);
#else
            byte[] preHash = DigestUtilities.DoFinal(m_preHashDigest);
            msgRepDigest.BlockUpdate(preHash, 0, preHash.Length);
#endif

            return msgRepDigest;
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
