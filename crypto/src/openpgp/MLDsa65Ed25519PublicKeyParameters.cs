using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Public key for the OpenPGP ML-DSA-65+Ed25519 composite signature scheme
    /// (<see cref="PublicKeyAlgorithmTag.MLDsa65_Ed25519"/>).
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
    public sealed class MLDsa65Ed25519PublicKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly Ed25519PublicKeyParameters m_ed25519Key;
        private readonly MLDsaPublicKeyParameters m_mlDsaKey;

        /// <summary>Create a composite public key from its two components.</summary>
        /// <param name="ed25519Key">The Ed25519 component.</param>
        /// <param name="mlDsaKey">The ML-DSA component, which must use the ML-DSA-65 parameter set.</param>
        public MLDsa65Ed25519PublicKeyParameters(Ed25519PublicKeyParameters ed25519Key,
            MLDsaPublicKeyParameters mlDsaKey)
            : base(privateKey: false)
        {
            m_ed25519Key = ed25519Key ?? throw new ArgumentNullException(nameof(ed25519Key));
            m_mlDsaKey = mlDsaKey ?? throw new ArgumentNullException(nameof(mlDsaKey));

            if (mlDsaKey.Parameters != MLDsaParameters.ml_dsa_65)
                throw new ArgumentException("ML-DSA key must use ML-DSA-65", nameof(mlDsaKey));
        }

        /// <summary>The Ed25519 component.</summary>
        public Ed25519PublicKeyParameters Ed25519Key => m_ed25519Key;

        /// <summary>The ML-DSA-65 component.</summary>
        public MLDsaPublicKeyParameters MLDsaKey => m_mlDsaKey;
    }
}
