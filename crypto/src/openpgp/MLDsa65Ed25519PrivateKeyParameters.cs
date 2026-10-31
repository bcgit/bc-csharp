using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Private key for the OpenPGP ML-DSA-65+Ed25519 composite signature scheme
    /// (<see cref="PublicKeyAlgorithmTag.MLDsa65_Ed25519"/>).
    /// </summary>
    /// <remarks>
    /// OpenPGP stores the ML-DSA secret key in seed format (RFC 9980 5.3.2.2), so the ML-DSA component must have a
    /// seed available.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5.3">
    /// Post-Quantum Cryptography in OpenPGP - Composite Signature Schemes with ML-DSA
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLDsa65Ed25519PrivateKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly Ed25519PrivateKeyParameters m_ed25519Key;
        private readonly MLDsaPrivateKeyParameters m_mlDsaKey;

        /// <summary>Generate a new composite private key, with the two components generated independently.</summary>
        /// <param name="random">The source of randomness.</param>
        public MLDsa65Ed25519PrivateKeyParameters(SecureRandom random)
            : base(privateKey: true)
        {
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            m_ed25519Key = new Ed25519PrivateKeyParameters(random);

            var mlDsaGenerator = new MLDsaKeyPairGenerator();
            mlDsaGenerator.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65));
            m_mlDsaKey = (MLDsaPrivateKeyParameters)mlDsaGenerator.GenerateKeyPair().Private;
        }

        /// <summary>Create a composite private key from its two components.</summary>
        /// <param name="ed25519Key">The Ed25519 component.</param>
        /// <param name="mlDsaKey">The ML-DSA component, which must use the ML-DSA-65 parameter set and have its seed
        /// available.</param>
        public MLDsa65Ed25519PrivateKeyParameters(Ed25519PrivateKeyParameters ed25519Key,
            MLDsaPrivateKeyParameters mlDsaKey)
            : base(privateKey: true)
        {
            m_ed25519Key = ed25519Key ?? throw new ArgumentNullException(nameof(ed25519Key));
            m_mlDsaKey = mlDsaKey ?? throw new ArgumentNullException(nameof(mlDsaKey));

            if (mlDsaKey.Parameters != MLDsaParameters.ml_dsa_65)
                throw new ArgumentException("ML-DSA key must use ML-DSA-65", nameof(mlDsaKey));
            if (mlDsaKey.GetSeed() == null)
                throw new ArgumentException("ML-DSA key must have a seed", nameof(mlDsaKey));
        }

        /// <summary>The Ed25519 component.</summary>
        public Ed25519PrivateKeyParameters Ed25519Key => m_ed25519Key;

        /// <summary>The ML-DSA-65 component.</summary>
        public MLDsaPrivateKeyParameters MLDsaKey => m_mlDsaKey;

        /// <summary>Derive the corresponding composite public key.</summary>
        public MLDsa65Ed25519PublicKeyParameters GeneratePublicKey() =>
            new MLDsa65Ed25519PublicKeyParameters(m_ed25519Key.GeneratePublicKey(), m_mlDsaKey.GetPublicKey());
    }
}
