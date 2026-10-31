using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// The composite signature schemes of RFC 9980 (section 5): an EdDSA signature and an ML-DSA signature are made
    /// independently over the same data, which is the digest of the OpenPGP signature (see
    /// <see cref="PgpDigestSigner"/>). The signature is the concatenation of the two, and it is only valid if both
    /// components are.
    /// </summary>
    internal sealed class PgpCompositeSigner
        : ISigner
    {
        private readonly PublicKeyAlgorithmTag m_algorithm;
        private readonly ISigner m_edSigner;
        private readonly MLDsaSigner m_mlDsaSigner;
        private readonly int m_edSignatureLength;
        private readonly int m_mlDsaSignatureLength;

        private bool m_forSigning;

        /// <param name="algorithm">
        /// <see cref="PublicKeyAlgorithmTag.MLDsa65_Ed25519"/> or <see cref="PublicKeyAlgorithmTag.MLDsa87_Ed448"/>.
        /// </param>
        internal PgpCompositeSigner(PublicKeyAlgorithmTag algorithm)
        {
            m_algorithm = algorithm;

            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
                m_edSigner = new Ed25519Signer();
                m_edSignatureLength = Ed25519.SignatureSize;
                m_mlDsaSigner = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
                m_mlDsaSignatureLength = 3309;
                break;
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
                m_edSigner = new Ed448Signer(Arrays.EmptyBytes);
                m_edSignatureLength = Ed448.SignatureSize;
                m_mlDsaSigner = new MLDsaSigner(MLDsaParameters.ml_dsa_87, deterministic: false);
                m_mlDsaSignatureLength = 4627;
                break;
            default:
                throw new ArgumentException("not a composite signature algorithm", nameof(algorithm));
            }
        }

        public string AlgorithmName => m_algorithm.ToString();

        /// <summary>The length of a composite signature in octets.</summary>
        internal int SignatureLength => m_edSignatureLength + m_mlDsaSignatureLength;

        public void Init(bool forSigning, ICipherParameters parameters)
        {
            ICipherParameters keyParameters = ParameterUtilities.GetRandom(parameters, out SecureRandom random);

            ICipherParameters edKey, mlDsaKey;
            if (m_algorithm == PublicKeyAlgorithmTag.MLDsa65_Ed25519)
            {
                if (forSigning)
                {
                    var key = keyParameters as MLDsa65Ed25519PrivateKeyParameters
                        ?? throw new InvalidKeyException("ML-DSA-65+Ed25519 private key required");
                    edKey = key.Ed25519Key;
                    mlDsaKey = key.MLDsaKey;
                }
                else
                {
                    var key = keyParameters as MLDsa65Ed25519PublicKeyParameters
                        ?? throw new InvalidKeyException("ML-DSA-65+Ed25519 public key required");
                    edKey = key.Ed25519Key;
                    mlDsaKey = key.MLDsaKey;
                }
            }
            else
            {
                if (forSigning)
                {
                    var key = keyParameters as MLDsa87Ed448PrivateKeyParameters
                        ?? throw new InvalidKeyException("ML-DSA-87+Ed448 private key required");
                    edKey = key.Ed448Key;
                    mlDsaKey = key.MLDsaKey;
                }
                else
                {
                    var key = keyParameters as MLDsa87Ed448PublicKeyParameters
                        ?? throw new InvalidKeyException("ML-DSA-87+Ed448 public key required");
                    edKey = key.Ed448Key;
                    mlDsaKey = key.MLDsaKey;
                }
            }

            m_forSigning = forSigning;

            m_edSigner.Init(forSigning, edKey);
            if (forSigning)
            {
                mlDsaKey = new ParametersWithRandom(mlDsaKey, CryptoServicesRegistrar.GetSecureRandom(random));
            }
            m_mlDsaSigner.Init(forSigning, mlDsaKey);
        }

        public void Update(byte input)
        {
            m_edSigner.Update(input);
            m_mlDsaSigner.Update(input);
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            m_edSigner.BlockUpdate(input, inOff, inLen);
            m_mlDsaSigner.BlockUpdate(input, inOff, inLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            m_edSigner.BlockUpdate(input);
            m_mlDsaSigner.BlockUpdate(input);
        }
#endif

        public int GetMaxSignatureSize() => SignatureLength;

        public byte[] GenerateSignature()
        {
            if (!m_forSigning)
                throw new InvalidOperationException("not initialised for signing");

            return Arrays.Concatenate(m_edSigner.GenerateSignature(), m_mlDsaSigner.GenerateSignature());
        }

        public bool VerifySignature(byte[] signature)
        {
            if (m_forSigning)
                throw new InvalidOperationException("not initialised for verification");

            // Both components consume the data, so both are always checked. A signature of the wrong length is not
            // a valid composite signature, whatever its components.
            bool lengthOk = signature != null && signature.Length == SignatureLength;
            byte[] edSignature = lengthOk
                ? Arrays.CopyOfRange(signature, 0, m_edSignatureLength)
                : new byte[m_edSignatureLength];
            byte[] mlDsaSignature = lengthOk
                ? Arrays.CopyOfRange(signature, m_edSignatureLength, SignatureLength)
                : new byte[m_mlDsaSignatureLength];

            bool edOk = m_edSigner.VerifySignature(edSignature);
            bool mlDsaOk = m_mlDsaSigner.VerifySignature(mlDsaSignature);
            return lengthOk & edOk & mlDsaOk;
        }

        public void Reset()
        {
            m_edSigner.Reset();
            m_mlDsaSigner.Reset();
        }
    }
}
