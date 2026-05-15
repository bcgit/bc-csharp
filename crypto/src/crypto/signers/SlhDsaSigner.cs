using System;
using System.IO;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers.SlhDsa;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>
    /// SLH-DSA (FIPS 205) signature primitive. Buffers the message via the streaming
    /// <see cref="ISigner"/> surface prefixed with the FIPS 205 context envelope and dispatches the
    /// whole buffer to the hypertree sign / verify routines on finalisation. The signer must be bound
    /// to the same <see cref="SlhDsaParameters.ParameterSet"/> as the key it is initialised with.
    /// Optional <see cref="ParametersWithContext"/> (up to 255 bytes) and
    /// <see cref="ParametersWithRandom"/> envelopes are unwrapped during <see cref="Init"/>.
    /// </summary>
    public sealed class SlhDsaSigner
        : ISigner
    {
        private readonly Buffer m_buffer = new Buffer();
        private readonly SlhDsaParameters m_parameters;
        private readonly bool m_deterministic;

        private SlhDsaPrivateKeyParameters m_privateKey;
        private SlhDsaPublicKeyParameters m_publicKey;
        private SecureRandom m_random;
        private SlhDsaEngine m_engine;

        /// <summary>
        /// Construct an SLH-DSA signer for the supplied parameter set. Only the pure variants are
        /// accepted; the HashSLH-DSA variants (those carrying a pre-hash OID) must go through their
        /// dedicated wrapper instead.
        /// </summary>
        /// <param name="parameters">The SLH-DSA parameter set; must be a pure (non-pre-hash) variant.</param>
        /// <param name="deterministic">When <c>true</c>, signature generation omits the optional
        /// per-signature randomiser (<c>addrnd</c>); otherwise an <c>n</c>-byte randomiser is drawn from
        /// the bound <see cref="SecureRandom"/>.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="parameters"/> is a HashSLH-DSA
        /// variant.</exception>
        public SlhDsaSigner(SlhDsaParameters parameters, bool deterministic)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (parameters.PreHashOid != null)
                throw new ArgumentException("cannot be used for HashSLH-DSA", nameof(parameters));

            m_parameters = parameters;
            m_deterministic = deterministic;
        }

        /// <inheritdoc/>
        public string AlgorithmName => m_parameters.Name;

        /// <summary>
        /// Initialise for signing (private key) or verification (public key). Accepts
        /// <see cref="ParametersWithContext"/> for a context up to 255 bytes and
        /// <see cref="ParametersWithRandom"/> for the non-deterministic signer's randomiser source.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">If the supplied context exceeds 255 bytes.</exception>
        /// <exception cref="InvalidCastException">If the unwrapped inner parameters are not an
        /// <see cref="SlhDsaPrivateKeyParameters"/> (signing) or <see cref="SlhDsaPublicKeyParameters"/>
        /// (verification).</exception>
        /// <exception cref="ArgumentException">If the key's parameter set differs from the one this
        /// signer was constructed for.</exception>
        public void Init(bool forSigning, ICipherParameters parameters)
        {
            parameters = ParameterUtilities.GetContext(parameters, minLen: 0, maxLen: 255, out var providedContext);

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

            m_buffer.Init(context: providedContext ?? Array.Empty<byte>());
        }

        /// <inheritdoc/>
        public void Update(byte input) => m_buffer.WriteByte(input);

        /// <inheritdoc/>
        public void BlockUpdate(byte[] input, int inOff, int inLen) => m_buffer.Write(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void BlockUpdate(ReadOnlySpan<byte> input) => m_buffer.Write(input);
#endif

        /// <summary>Length in bytes of the signatures this signer produces (FIPS 205
        /// <c>SignatureLength</c>).</summary>
        public int GetMaxSignatureSize() => m_engine.SignatureLength;

        /// <summary>Finalise the buffered message and produce the signature. Buffer is reset on return.</summary>
        /// <exception cref="InvalidOperationException">If the signer was initialised for verification,
        /// not signing.</exception>
        public byte[] GenerateSignature()
        {
            if (m_privateKey == null)
                throw new InvalidOperationException("SlhDsaSigner not initialised for signature generation.");

            return m_buffer.GenerateSignature(m_privateKey, m_engine, m_random);
        }

        /// <summary>
        /// Finalise the buffered message and verify <paramref name="signature"/>. Buffer is reset on
        /// return.
        /// </summary>
        /// <returns><c>true</c> if the signature is valid for the accumulated message and bound public
        /// key; otherwise <c>false</c>.</returns>
        /// <exception cref="InvalidOperationException">If the signer was initialised for signing, not
        /// verification.</exception>
        public bool VerifySignature(byte[] signature)
        {
            if (m_publicKey == null)
                throw new InvalidOperationException("SlhDsaSigner not initialised for verification");

            return m_buffer.VerifySignature(m_publicKey, m_engine, signature);
        }

        /// <summary>Truncate the buffered message back to the captured context prefix.</summary>
        public void Reset() => m_buffer.Reset();

        private SlhDsaEngine GetEngine(SlhDsaParameters keyParameters)
        {
            var keyParameterSet = keyParameters.ParameterSet;

            if (keyParameterSet != m_parameters.ParameterSet)
                throw new ArgumentException("Mismatching key parameter set", nameof(keyParameters));

            return keyParameterSet.GetEngine();
        }

        private sealed class Buffer : MemoryStream
        {
            private int m_prefixLength;

            internal void Init(byte[] context)
            {
                lock (this)
                {
                    TruncateAndClear(newLength: 0);

                    WriteByte(0x00);
                    WriteByte((byte)context.Length);
                    Write(context, 0, context.Length);

                    m_prefixLength = Convert.ToInt32(Length);
                }
            }

            internal byte[] GenerateSignature(SlhDsaPrivateKeyParameters privateKey, SlhDsaEngine engine,
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

            internal bool VerifySignature(SlhDsaPublicKeyParameters publicKey, SlhDsaEngine engine,
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
