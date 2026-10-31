using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Public key for the OpenPGP ML-KEM-768+X25519 composite KEM
    /// (<see cref="PublicKeyAlgorithmTag.MLKem768_X25519"/>).
    /// </summary>
    /// <remarks>
    /// The two component keys are combined by the OpenPGP-specific key combiner of RFC 9980; this type is not a
    /// general purpose hybrid KEM key.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4.2">
    /// Post-Quantum Cryptography in OpenPGP - Composite Encryption Schemes with ML-KEM
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLKem768X25519PublicKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly X25519PublicKeyParameters m_x25519Key;
        private readonly MLKemPublicKeyParameters m_mlKemKey;

        /// <summary>Create a composite public key from its two components.</summary>
        /// <param name="x25519Key">The X25519 component.</param>
        /// <param name="mlKemKey">The ML-KEM component, which must use the ML-KEM-768 parameter set.</param>
        public MLKem768X25519PublicKeyParameters(X25519PublicKeyParameters x25519Key,
            MLKemPublicKeyParameters mlKemKey)
            : base(privateKey: false)
        {
            m_x25519Key = x25519Key ?? throw new ArgumentNullException(nameof(x25519Key));
            m_mlKemKey = mlKemKey ?? throw new ArgumentNullException(nameof(mlKemKey));

            if (mlKemKey.Parameters != MLKemParameters.ml_kem_768)
                throw new ArgumentException("ML-KEM key must use ML-KEM-768", nameof(mlKemKey));
        }

        /// <summary>The X25519 component.</summary>
        public X25519PublicKeyParameters X25519Key => m_x25519Key;

        /// <summary>The ML-KEM-768 component.</summary>
        public MLKemPublicKeyParameters MLKemKey => m_mlKemKey;
    }
}
