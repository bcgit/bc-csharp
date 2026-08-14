using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// A Composite ML-DSA public key: the ML-DSA component paired with a traditional component.
    /// </summary>
    /// <remarks>
    /// The wire form is the plain concatenation of the two component public keys, in that order, with no
    /// framing: the ML-DSA half has a fixed length determined by the parameter set, so the split point is
    /// unambiguous. That concatenation is what appears in the <c>subjectPublicKey</c> BIT STRING of a
    /// composite <c>SubjectPublicKeyInfo</c>.
    /// </remarks>
    public sealed class CompositeMLDsaPublicKeyParameters
        : CompositeMLDsaKeyParameters
    {
        /// <summary>
        /// Decode a composite public key from the concatenated component encoding.
        /// </summary>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> or
        /// <paramref name="encoding"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="encoding"/> is too short to hold the ML-DSA
        /// component, or either component fails to decode.</exception>
        public static CompositeMLDsaPublicKeyParameters FromEncoding(CompositeMLDsaParameters parameters,
            byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));

            int mlDsaLength = parameters.MLDsaPublicKeyLength;
            if (encoding.Length <= mlDsaLength)
                throw new ArgumentException("malformed composite public key: no traditional component",
                    nameof(encoding));

            var mlDsaKey = MLDsaPublicKeyParameters.FromEncoding(parameters.MLDsaParameters,
                Arrays.CopyOfRange(encoding, 0, mlDsaLength));

            var traditionalKey = DecodeTraditionalKey(parameters,
                Arrays.CopyOfRange(encoding, mlDsaLength, encoding.Length));

            return new CompositeMLDsaPublicKeyParameters(parameters, mlDsaKey, traditionalKey);
        }

        private readonly MLDsaPublicKeyParameters m_mlDsaPublicKey;
        private readonly AsymmetricKeyParameter m_traditionalPublicKey;

        /// <summary>
        /// Create a composite public key from its two components. The components are not verified against
        /// each other beyond the checks implied by <paramref name="parameters"/>; a mismatched pairing fails
        /// later, when the component algorithms reject the key.
        /// </summary>
        /// <exception cref="ArgumentNullException">If any argument is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If either component is a private key, or the ML-DSA component
        /// does not use the parameter set required by <paramref name="parameters"/>.</exception>
        public CompositeMLDsaPublicKeyParameters(CompositeMLDsaParameters parameters,
            MLDsaPublicKeyParameters mlDsaPublicKey, AsymmetricKeyParameter traditionalPublicKey)
            : base(isPrivate: false, parameters)
        {
            if (mlDsaPublicKey == null)
                throw new ArgumentNullException(nameof(mlDsaPublicKey));
            if (traditionalPublicKey == null)
                throw new ArgumentNullException(nameof(traditionalPublicKey));
            if (traditionalPublicKey.IsPrivate)
                throw new ArgumentException("expected a public key", nameof(traditionalPublicKey));
            if (mlDsaPublicKey.Parameters.ParameterSet != parameters.MLDsaParameters.ParameterSet)
                throw new ArgumentException("mismatching ML-DSA parameter set", nameof(mlDsaPublicKey));

            m_mlDsaPublicKey = mlDsaPublicKey;
            m_traditionalPublicKey = traditionalPublicKey;
        }

        /// <summary>The ML-DSA component.</summary>
        public MLDsaPublicKeyParameters MLDsaPublicKey => m_mlDsaPublicKey;

        /// <summary>The traditional (RSA, ECDSA, Ed25519 or Ed448) component.</summary>
        public AsymmetricKeyParameter TraditionalPublicKey => m_traditionalPublicKey;

        /// <summary>The concatenated component encoding (see the class remarks).</summary>
        public byte[] GetEncoded() => Arrays.Concatenate(m_mlDsaPublicKey.GetEncoded(),
            EncodeTraditionalKey(Parameters, m_traditionalPublicKey));

        private static AsymmetricKeyParameter DecodeTraditionalKey(CompositeMLDsaParameters parameters,
            byte[] encoding)
        {
            switch (parameters.KeyType)
            {
            case CompositeMLDsaParameters.TraditionalKeyType.Ed25519:
                return new Ed25519PublicKeyParameters(encoding);
            case CompositeMLDsaParameters.TraditionalKeyType.Ed448:
                return new Ed448PublicKeyParameters(encoding);
            case CompositeMLDsaParameters.TraditionalKeyType.ECDsa:
            {
                var domainParameters = ECNamedDomainParameters.LookupOid(parameters.CurveOid);
                var q = domainParameters.Curve.DecodePoint(encoding);
                return new ECPublicKeyParameters(q, domainParameters);
            }
            case CompositeMLDsaParameters.TraditionalKeyType.Rsa:
            {
                var rsaPublicKey = RsaPublicKeyStructure.GetInstance(encoding);
                return new RsaKeyParameters(isPrivate: false, rsaPublicKey.Modulus, rsaPublicKey.PublicExponent);
            }
            default:
                throw new InvalidOperationException();
            }
        }

        private static byte[] EncodeTraditionalKey(CompositeMLDsaParameters parameters, AsymmetricKeyParameter key)
        {
            switch (parameters.KeyType)
            {
            case CompositeMLDsaParameters.TraditionalKeyType.Ed25519:
                return ((Ed25519PublicKeyParameters)key).GetEncoded();
            case CompositeMLDsaParameters.TraditionalKeyType.Ed448:
                return ((Ed448PublicKeyParameters)key).GetEncoded();
            case CompositeMLDsaParameters.TraditionalKeyType.ECDsa:
                return ((ECPublicKeyParameters)key).Q.GetEncoded(compressed: false);
            case CompositeMLDsaParameters.TraditionalKeyType.Rsa:
            {
                var rsaKey = (RsaKeyParameters)key;
                return new RsaPublicKeyStructure(rsaKey.Modulus, rsaKey.Exponent).GetEncoded(Asn1Encodable.Der);
            }
            default:
                throw new InvalidOperationException();
            }
        }
    }
}
