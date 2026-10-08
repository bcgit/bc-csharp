using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Public key for the OpenPGP ML-KEM-1024+X448 composite KEM
    /// (<see cref="PublicKeyAlgorithmTag.MLKem1024_X448"/>).
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
    public sealed class MLKem1024X448PublicKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly X448PublicKeyParameters m_x448Key;
        private readonly MLKemPublicKeyParameters m_mlKemKey;

        /// <summary>Create a composite public key from its two components.</summary>
        /// <param name="x448Key">The X448 component.</param>
        /// <param name="mlKemKey">The ML-KEM component, which must use the ML-KEM-1024 parameter set.</param>
        public MLKem1024X448PublicKeyParameters(X448PublicKeyParameters x448Key,
            MLKemPublicKeyParameters mlKemKey)
            : base(privateKey: false)
        {
            m_x448Key = x448Key ?? throw new ArgumentNullException(nameof(x448Key));
            m_mlKemKey = mlKemKey ?? throw new ArgumentNullException(nameof(mlKemKey));

            if (mlKemKey.Parameters != MLKemParameters.ml_kem_1024)
                throw new ArgumentException("ML-KEM key must use ML-KEM-1024", nameof(mlKemKey));
        }

        /// <summary>The X448 component.</summary>
        public X448PublicKeyParameters X448Key => m_x448Key;

        /// <summary>The ML-KEM-1024 component.</summary>
        public MLKemPublicKeyParameters MLKemKey => m_mlKemKey;
    }
}
