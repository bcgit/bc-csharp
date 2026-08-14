using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// A Composite ML-DSA private key: the ML-DSA component paired with a traditional component.
    /// </summary>
    /// <remarks>
    /// The wire form is the plain concatenation of the ML-DSA 32-byte seed and the traditional private key,
    /// with no framing. The traditional half is the bare key material as it would appear inside its own
    /// PKCS#8 <c>privateKey</c> OCTET STRING — a DER <c>RSAPrivateKey</c>, a DER <c>ECPrivateKey</c> (carrying
    /// the curve but not the public point), or the raw Ed25519/Ed448 secret. Because the ML-DSA half is a
    /// seed, a composite private key can only be encoded when its ML-DSA component retains one.
    /// </remarks>
    public sealed class CompositeMLDsaPrivateKeyParameters
        : CompositeMLDsaKeyParameters
    {
        /// <summary>
        /// Decode a composite private key from the concatenated component encoding.
        /// </summary>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> or
        /// <paramref name="encoding"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="encoding"/> is too short to hold the ML-DSA
        /// seed, or either component fails to decode.</exception>
        public static CompositeMLDsaPrivateKeyParameters FromEncoding(CompositeMLDsaParameters parameters,
            byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));

            int seedLength = parameters.MLDsaSeedLength;
            if (encoding.Length <= seedLength)
                throw new ArgumentException("malformed composite private key: body shorter than the ML-DSA seed",
                    nameof(encoding));

            var mlDsaKey = MLDsaPrivateKeyParameters.FromSeed(parameters.MLDsaParameters,
                Arrays.CopyOfRange(encoding, 0, seedLength));

            var traditionalKey = DecodeTraditionalKey(parameters,
                Arrays.CopyOfRange(encoding, seedLength, encoding.Length));

            return new CompositeMLDsaPrivateKeyParameters(parameters, mlDsaKey, traditionalKey);
        }

        private readonly MLDsaPrivateKeyParameters m_mlDsaPrivateKey;
        private readonly AsymmetricKeyParameter m_traditionalPrivateKey;

        /// <summary>
        /// Create a composite private key from its two components.
        /// </summary>
        /// <exception cref="ArgumentNullException">If any argument is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If either component is a public key, or the ML-DSA component
        /// does not use the parameter set required by <paramref name="parameters"/>.</exception>
        public CompositeMLDsaPrivateKeyParameters(CompositeMLDsaParameters parameters,
            MLDsaPrivateKeyParameters mlDsaPrivateKey, AsymmetricKeyParameter traditionalPrivateKey)
            : base(isPrivate: true, parameters)
        {
            if (mlDsaPrivateKey == null)
                throw new ArgumentNullException(nameof(mlDsaPrivateKey));
            if (traditionalPrivateKey == null)
                throw new ArgumentNullException(nameof(traditionalPrivateKey));
            if (!traditionalPrivateKey.IsPrivate)
                throw new ArgumentException("expected a private key", nameof(traditionalPrivateKey));
            if (mlDsaPrivateKey.Parameters.ParameterSet != parameters.MLDsaParameters.ParameterSet)
                throw new ArgumentException("mismatching ML-DSA parameter set", nameof(mlDsaPrivateKey));

            m_mlDsaPrivateKey = mlDsaPrivateKey;
            m_traditionalPrivateKey = traditionalPrivateKey;
        }

        /// <summary>The ML-DSA component.</summary>
        public MLDsaPrivateKeyParameters MLDsaPrivateKey => m_mlDsaPrivateKey;

        /// <summary>The traditional (RSA, ECDSA, Ed25519 or Ed448) component.</summary>
        public AsymmetricKeyParameter TraditionalPrivateKey => m_traditionalPrivateKey;

        /// <summary>
        /// The concatenated component encoding (see the class remarks).
        /// </summary>
        /// <exception cref="InvalidOperationException">If the ML-DSA component was imported from an expanded
        /// encoding and so has no seed to encode.</exception>
        public byte[] GetEncoded()
        {
            byte[] seed = m_mlDsaPrivateKey.GetSeed();
            if (seed == null)
                throw new InvalidOperationException("composite private key requires an ML-DSA seed to encode");

            return Arrays.Concatenate(seed, EncodeTraditionalKey(Parameters, m_traditionalPrivateKey));
        }

        /// <summary>Derive the matching composite public key.</summary>
        public CompositeMLDsaPublicKeyParameters GetPublicKey() =>
            new CompositeMLDsaPublicKeyParameters(Parameters, m_mlDsaPrivateKey.GetPublicKey(),
                GetTraditionalPublicKey());

        private AsymmetricKeyParameter GetTraditionalPublicKey()
        {
            switch (Parameters.KeyType)
            {
            case CompositeMLDsaParameters.TraditionalKeyType.Ed25519:
                return ((Ed25519PrivateKeyParameters)m_traditionalPrivateKey).GeneratePublicKey();
            case CompositeMLDsaParameters.TraditionalKeyType.Ed448:
                return ((Ed448PrivateKeyParameters)m_traditionalPrivateKey).GeneratePublicKey();
            case CompositeMLDsaParameters.TraditionalKeyType.ECDsa:
                return ECKeyPairGenerator.GetCorrespondingPublicKey(
                    (ECPrivateKeyParameters)m_traditionalPrivateKey);
            case CompositeMLDsaParameters.TraditionalKeyType.Rsa:
            {
                var rsaKey = (RsaKeyParameters)m_traditionalPrivateKey;
                if (rsaKey is RsaPrivateCrtKeyParameters crtKey)
                    return new RsaKeyParameters(isPrivate: false, crtKey.Modulus, crtKey.PublicExponent);

                throw new InvalidOperationException("cannot derive RSA public key from a non-CRT private key");
            }
            default:
                throw new InvalidOperationException();
            }
        }

        private static AsymmetricKeyParameter DecodeTraditionalKey(CompositeMLDsaParameters parameters,
            byte[] encoding)
        {
            switch (parameters.KeyType)
            {
            case CompositeMLDsaParameters.TraditionalKeyType.Ed25519:
                return new Ed25519PrivateKeyParameters(encoding);
            case CompositeMLDsaParameters.TraditionalKeyType.Ed448:
                return new Ed448PrivateKeyParameters(encoding);
            case CompositeMLDsaParameters.TraditionalKeyType.ECDsa:
            {
                var ecPrivateKey = ECPrivateKeyStructure.GetInstance(encoding);
                var domainParameters = ECNamedDomainParameters.LookupOid(parameters.CurveOid);
                return new ECPrivateKeyParameters(ecPrivateKey.GetKey(), domainParameters);
            }
            case CompositeMLDsaParameters.TraditionalKeyType.Rsa:
                return new RsaPrivateCrtKeyParameters(RsaPrivateKeyStructure.GetInstance(encoding));
            default:
                throw new InvalidOperationException();
            }
        }

        private static byte[] EncodeTraditionalKey(CompositeMLDsaParameters parameters, AsymmetricKeyParameter key)
        {
            switch (parameters.KeyType)
            {
            case CompositeMLDsaParameters.TraditionalKeyType.Ed25519:
                return ((Ed25519PrivateKeyParameters)key).GetEncoded();
            case CompositeMLDsaParameters.TraditionalKeyType.Ed448:
                return ((Ed448PrivateKeyParameters)key).GetEncoded();
            case CompositeMLDsaParameters.TraditionalKeyType.ECDsa:
            {
                var ecKey = (ECPrivateKeyParameters)key;

                // NOTE: The composite form carries the curve but omits the optional public point.
                var ecPrivateKey = new ECPrivateKeyStructure(ecKey.Parameters.N.BitLength, ecKey.D,
                    new X962Parameters(parameters.CurveOid));

                return ecPrivateKey.GetEncoded(Asn1Encodable.Der);
            }
            case CompositeMLDsaParameters.TraditionalKeyType.Rsa:
            {
                if (key is RsaPrivateCrtKeyParameters crtKey)
                {
                    var rsaPrivateKey = new RsaPrivateKeyStructure(crtKey.Modulus, crtKey.PublicExponent,
                        crtKey.Exponent, crtKey.P, crtKey.Q, crtKey.DP, crtKey.DQ, crtKey.QInv);

                    return rsaPrivateKey.GetEncoded(Asn1Encodable.Der);
                }

                throw new InvalidOperationException("cannot encode a non-CRT RSA private key");
            }
            default:
                throw new InvalidOperationException();
            }
        }
    }
}
