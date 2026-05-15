using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers.MLDsa;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>
    /// ML-DSA (FIPS 204) signature primitive. Accumulates the message via the streaming
    /// <see cref="ISigner"/> surface and dispatches it through the FIPS 204 message-representative
    /// construction. The signer must be bound to the same <see cref="MLDsaParameters.ParameterSet"/> as
    /// the key it is initialised with. Optional <see cref="ParametersWithContext"/> (up to 255 bytes)
    /// and <see cref="ParametersWithRandom"/> envelopes are unwrapped during <see cref="Init"/>.
    /// </summary>
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

        /// <summary>
        /// Construct an ML-DSA signer for the supplied parameter set. Only the pure variants are
        /// accepted; the HashML-DSA variants (those carrying a pre-hash OID) must go through their
        /// dedicated wrapper instead.
        /// </summary>
        /// <param name="parameters">The ML-DSA parameter set; must be a pure (non-pre-hash) variant.</param>
        /// <param name="deterministic">When <c>true</c>, signature generation uses the FIPS 204
        /// deterministic mode (no <see cref="SecureRandom"/> draw); otherwise a fresh per-signature
        /// nonce is sampled.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="parameters"/> is a HashML-DSA
        /// variant.</exception>
        public MLDsaSigner(MLDsaParameters parameters, bool deterministic)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (parameters.PreHashOid != null)
                throw new ArgumentException("cannot be used for HashML-DSA", nameof(parameters));

            m_parameters = parameters;
            m_deterministic = deterministic;
        }

        /// <inheritdoc/>
        public string AlgorithmName => m_parameters.Name;

        /// <summary>
        /// Initialise for signing (private key) or verification (public key). Accepts
        /// <see cref="ParametersWithContext"/> for a context up to 255 bytes and
        /// <see cref="ParametersWithRandom"/> for a non-deterministic signer's nonce source.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">If the supplied context exceeds 255 bytes.</exception>
        /// <exception cref="InvalidCastException">If the unwrapped inner parameters are not an
        /// <see cref="MLDsaPrivateKeyParameters"/> (signing) or <see cref="MLDsaPublicKeyParameters"/>
        /// (verification).</exception>
        /// <exception cref="ArgumentException">If the key's parameter set differs from the one this
        /// signer was constructed for.</exception>
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

        /// <inheritdoc/>
        public void Update(byte input) => m_msgRepDigest.Update(input);

        /// <inheritdoc/>
        public void BlockUpdate(byte[] input, int inOff, int inLen) => m_msgRepDigest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void BlockUpdate(ReadOnlySpan<byte> input) => m_msgRepDigest.BlockUpdate(input);
#endif

        /// <summary>Length in bytes of the signatures this signer produces (FIPS 204
        /// <c>CryptoBytes</c>).</summary>
        public int GetMaxSignatureSize() => m_engine.CryptoBytes;

        /// <summary>
        /// Finalise the message representative and produce the signature. Internally calls
        /// <see cref="Reset"/> on success.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the signer was initialised for verification,
        /// not signing.</exception>
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

        /// <summary>
        /// Finalise the message representative and verify <paramref name="signature"/>. Internally calls
        /// <see cref="Reset"/> on success.
        /// </summary>
        /// <returns><c>true</c> if the signature is valid for the accumulated message and bound public
        /// key; otherwise <c>false</c>.</returns>
        /// <exception cref="InvalidOperationException">If the signer was initialised for signing, not
        /// verification.</exception>
        public bool VerifySignature(byte[] signature)
        {
            if (m_publicKey == null)
                throw new InvalidOperationException("MLDsaSigner not initialised for verification");

            bool result = m_engine.MsgRepEndVerifyInternal(m_msgRepDigest, signature, signature.Length,
                m_publicKey.m_rho, encT1: m_publicKey.m_t1);

            Reset();
            return result;
        }

        /// <summary>
        /// Reset the streaming digest and re-seed it with the bound public-key hash and the captured
        /// context, ready for another sign/verify pass against the same key.
        /// </summary>
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
