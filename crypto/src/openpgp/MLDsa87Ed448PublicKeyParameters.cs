using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Public key for the OpenPGP ML-DSA-87+Ed448 composite signature scheme
    /// (<see cref="PublicKeyAlgorithmTag.MLDsa87_Ed448"/>).
    /// </summary>
    /// <remarks>
    /// Both component signatures are made over the same digest and are verified independently; this type is not a
    /// general purpose hybrid signature key.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5.3">
    /// Post-Quantum Cryptography in OpenPGP - Composite Signature Schemes with ML-DSA
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLDsa87Ed448PublicKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly Ed448PublicKeyParameters m_ed448Key;
        private readonly MLDsaPublicKeyParameters m_mlDsaKey;

        /// <summary>Create a composite public key from its two components.</summary>
        /// <param name="ed448Key">The Ed448 component.</param>
        /// <param name="mlDsaKey">The ML-DSA component, which must use the ML-DSA-87 parameter set.</param>
        public MLDsa87Ed448PublicKeyParameters(Ed448PublicKeyParameters ed448Key,
            MLDsaPublicKeyParameters mlDsaKey)
            : base(privateKey: false)
        {
            m_ed448Key = ed448Key ?? throw new ArgumentNullException(nameof(ed448Key));
            m_mlDsaKey = mlDsaKey ?? throw new ArgumentNullException(nameof(mlDsaKey));

            if (mlDsaKey.Parameters != MLDsaParameters.ml_dsa_87)
                throw new ArgumentException("ML-DSA key must use ML-DSA-87", nameof(mlDsaKey));
        }

        /// <summary>The Ed448 component.</summary>
        public Ed448PublicKeyParameters Ed448Key => m_ed448Key;

        /// <summary>The ML-DSA-87 component.</summary>
        public MLDsaPublicKeyParameters MLDsaKey => m_mlDsaKey;
    }
}
