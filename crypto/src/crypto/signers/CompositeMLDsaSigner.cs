using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>
    /// Composite ML-DSA signature primitive, as specified by
    /// <a href="https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/">Composite ML-DSA for use
    /// in X.509 Public Key Infrastructure and CMS</a>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The message is first reduced to a message representative that binds both components to the same
    /// combination and context:
    /// </para>
    /// <code>M' = Prefix || Domain || len(ctx) || ctx || PH(M)</code>
    /// <para>
    /// <c>Prefix</c> is the fixed ASCII string <c>CompositeAlgorithmSignatures2025</c>, <c>Domain</c> is the
    /// per-combination separator from <see cref="CompositeMLDsaParameters"/>, and <c>PH</c> is that
    /// combination's pre-hash. Both components then sign <c>M'</c> — the ML-DSA component additionally taking
    /// <c>Domain</c> as its FIPS 204 context — and the composite signature is the concatenation
    /// <c>mldsaSig || tradSig</c>. Verification succeeds only if both components verify.
    /// </para>
    /// <para>
    /// A composite signature is not a proof of anything about either component in isolation: a caller must
    /// treat the pair as a single signature, which is what this class exposes.
    /// </para>
    /// </remarks>
    public sealed class CompositeMLDsaSigner
        : ISigner
    {
        // The ASCII string "CompositeAlgorithmSignatures2025"
        private static readonly byte[] Prefix = Strings.ToByteArray("CompositeAlgorithmSignatures2025");

        private readonly CompositeMLDsaParameters m_parameters;
        private readonly bool m_preHashed;
        private readonly IDigest m_digest;
        private readonly byte[] m_domain;

        private readonly MLDsaSigner m_mlDsaSigner;
        private readonly ISigner m_traditionalSigner;

        private byte[] m_context;
        private bool m_forSigning;
        private bool m_initialised;

        // Only used in pre-hashed mode, where it buffers the caller-supplied PH(M).
        private byte[] m_preHashBuffer;
        private int m_preHashBufferPos;

        /// <summary>
        /// Construct a signer that hashes the message itself.
        /// </summary>
        /// <param name="parameters">The composite combination to use.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
        public CompositeMLDsaSigner(CompositeMLDsaParameters parameters)
            : this(parameters, preHashed: false)
        {
        }

        /// <summary>
        /// Construct a signer, optionally in pre-hashed mode.
        /// </summary>
        /// <param name="parameters">The composite combination to use.</param>
        /// <param name="preHashed">When <c>true</c>, the data supplied through <see cref="Update(byte)"/> and
        /// <c>BlockUpdate</c> is taken to be <c>PH(M)</c> itself rather than the message; it must then be
        /// exactly the pre-hash output length. This lets a caller hash out-of-band, for instance when the
        /// message is not available in one place.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
        public CompositeMLDsaSigner(CompositeMLDsaParameters parameters, bool preHashed)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            m_preHashed = preHashed;

            m_digest = DigestUtilities.GetDigest(parameters.PreHashAlgorithm);
            m_domain = parameters.GetDomain();

            m_mlDsaSigner = new MLDsaSigner(parameters.MLDsaParameters, deterministic: false);
            m_traditionalSigner = SignerUtilities.GetSigner(parameters.TraditionalSignatureAlgorithm);

            if (preHashed)
            {
                m_preHashBuffer = new byte[m_digest.GetDigestSize()];
            }
        }

        /// <inheritdoc/>
        public string AlgorithmName => m_parameters.Name;

        /// <summary>
        /// Initialise for signing (private key) or verification (public key). Accepts
        /// <see cref="ParametersWithContext"/> for a context up to 255 bytes, and
        /// <see cref="ParametersWithRandom"/> to supply the randomness the component signers need.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">If the supplied context exceeds 255 bytes.</exception>
        /// <exception cref="InvalidCastException">If the unwrapped inner parameters are not a
        /// <see cref="CompositeMLDsaPrivateKeyParameters"/> (signing) or
        /// <see cref="CompositeMLDsaPublicKeyParameters"/> (verification).</exception>
        /// <exception cref="ArgumentException">If the key is bound to a different combination.</exception>
        public void Init(bool forSigning, ICipherParameters parameters)
        {
            // A failed re-initialisation must leave the signer unusable rather than silently reusing the
            // previously bound key.
            m_initialised = false;

            parameters = ParameterUtilities.GetContext(parameters, minLen: 0, maxLen: 255, out var providedContext);
            parameters = ParameterUtilities.GetRandom(parameters, out var providedRandom);

            m_context = providedContext ?? Array.Empty<byte>();
            m_forSigning = forSigning;

            ICipherParameters mlDsaKey, traditionalKey;
            if (forSigning)
            {
                var privateKey = (CompositeMLDsaPrivateKeyParameters)parameters;
                CheckParameters(privateKey.Parameters);

                mlDsaKey = privateKey.MLDsaPrivateKey;
                traditionalKey = privateKey.TraditionalPrivateKey;
            }
            else
            {
                var publicKey = (CompositeMLDsaPublicKeyParameters)parameters;
                CheckParameters(publicKey.Parameters);

                mlDsaKey = publicKey.MLDsaPublicKey;
                traditionalKey = publicKey.TraditionalPublicKey;
            }

            /*
             * The ML-DSA component takes the domain separator as its FIPS 204 context. MLDsaSigner unwraps the
             * context envelope before the random one, so the context has to be the outer of the two.
             */
            var mlDsaParameters = new ParametersWithContext(
                ParameterUtilities.WithRandom(mlDsaKey, providedRandom), m_domain);

            /*
             * Ed25519/Ed448 are deterministic and their signers reject a ParametersWithRandom envelope, so the
             * random is only forwarded to the component algorithms that can consume it.
             */
            if (m_parameters.KeyType != CompositeMLDsaParameters.TraditionalKeyType.Ed25519 &&
                m_parameters.KeyType != CompositeMLDsaParameters.TraditionalKeyType.Ed448)
            {
                traditionalKey = ParameterUtilities.WithRandom(traditionalKey, providedRandom);
            }

            m_mlDsaSigner.Init(forSigning, mlDsaParameters);
            m_traditionalSigner.Init(forSigning, traditionalKey);

            m_initialised = true;

            Reset();
        }

        /// <inheritdoc/>
        public void Update(byte input)
        {
            if (m_preHashed)
            {
                if (m_preHashBufferPos >= m_preHashBuffer.Length)
                    throw new InvalidOperationException("provided pre-hash digest is the wrong length");

                m_preHashBuffer[m_preHashBufferPos++] = input;
            }
            else
            {
                m_digest.Update(input);
            }
        }

        /// <inheritdoc/>
        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            if (m_preHashed)
            {
                if (inLen > m_preHashBuffer.Length - m_preHashBufferPos)
                    throw new InvalidOperationException("provided pre-hash digest is the wrong length");

                Array.Copy(input, inOff, m_preHashBuffer, m_preHashBufferPos, inLen);
                m_preHashBufferPos += inLen;
            }
            else
            {
                m_digest.BlockUpdate(input, inOff, inLen);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (m_preHashed)
            {
                if (input.Length > m_preHashBuffer.Length - m_preHashBufferPos)
                    throw new InvalidOperationException("provided pre-hash digest is the wrong length");

                input.CopyTo(m_preHashBuffer.AsSpan(m_preHashBufferPos));
                m_preHashBufferPos += input.Length;
            }
            else
            {
                m_digest.BlockUpdate(input);
            }
        }
#endif

        /// <summary>
        /// Upper bound in bytes on the composite signatures this signer produces: the fixed ML-DSA half plus
        /// the traditional signer's own bound. ECDSA signatures are DER-encoded and so vary in length, which
        /// makes this a bound rather than an exact size.
        /// </summary>
        public int GetMaxSignatureSize() =>
            m_parameters.MLDsaSignatureLength + m_traditionalSigner.GetMaxSignatureSize();

        /// <inheritdoc/>
        public byte[] GenerateSignature()
        {
            if (!m_initialised || !m_forSigning)
                throw new InvalidOperationException("CompositeMLDsaSigner not initialised for signature generation");

            ProcessMessageRepresentative();

            byte[] mlDsaSignature = m_mlDsaSigner.GenerateSignature();
            byte[] traditionalSignature = m_traditionalSigner.GenerateSignature();

            Reset();

            return Arrays.Concatenate(mlDsaSignature, traditionalSignature);
        }

        /// <inheritdoc/>
        public bool VerifySignature(byte[] signature)
        {
            if (!m_initialised || m_forSigning)
                throw new InvalidOperationException("CompositeMLDsaSigner not initialised for verification");

            int mlDsaSignatureLength = m_parameters.MLDsaSignatureLength;
            if (signature == null || signature.Length <= mlDsaSignatureLength)
            {
                Reset();
                return false;
            }

            ProcessMessageRepresentative();

            /*
             * Both components are verified even once one has failed: the component verifications are
             * independent, and reporting which half failed would tell an attacker more than the single bit
             * the caller asked for.
             */
            bool mlDsaOk = m_mlDsaSigner.VerifySignature(
                Arrays.CopyOfRange(signature, 0, mlDsaSignatureLength));
            bool traditionalOk = m_traditionalSigner.VerifySignature(
                Arrays.CopyOfRange(signature, mlDsaSignatureLength, signature.Length));

            Reset();

            return mlDsaOk & traditionalOk;
        }

        /// <inheritdoc/>
        public void Reset()
        {
            m_digest.Reset();
            m_preHashBufferPos = 0;

            if (m_initialised)
            {
                m_mlDsaSigner.Reset();
                m_traditionalSigner.Reset();
            }
        }

        private void CheckParameters(CompositeMLDsaParameters keyParameters)
        {
            if (keyParameters != m_parameters)
                throw new ArgumentException("Mismatching composite parameters", nameof(keyParameters));
        }

        /*
         * M' = Prefix || Domain || len(ctx) || ctx || PH(M), fed to both component signers.
         */
        private void ProcessMessageRepresentative()
        {
            byte[] preHash = GetPreHash();

            byte[] messageRepresentative = Arrays.ConcatenateAll(Prefix, m_domain,
                new byte[]{ (byte)m_context.Length }, m_context, preHash);

            m_mlDsaSigner.BlockUpdate(messageRepresentative, 0, messageRepresentative.Length);
            m_traditionalSigner.BlockUpdate(messageRepresentative, 0, messageRepresentative.Length);
        }

        private byte[] GetPreHash()
        {
            byte[] preHash = new byte[m_digest.GetDigestSize()];

            if (m_preHashed)
            {
                if (m_preHashBufferPos != preHash.Length)
                    throw new InvalidOperationException("provided pre-hash digest is the wrong length");

                Array.Copy(m_preHashBuffer, preHash, preHash.Length);
                m_preHashBufferPos = 0;
            }
            else
            {
                m_digest.DoFinal(preHash, 0);
            }

            return preHash;
        }
    }
}
