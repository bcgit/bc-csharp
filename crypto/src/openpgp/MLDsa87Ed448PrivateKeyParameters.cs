using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Private key for the OpenPGP ML-DSA-87+Ed448 composite signature scheme
    /// (<see cref="PublicKeyAlgorithmTag.MLDsa87_Ed448"/>).
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
    public sealed class MLDsa87Ed448PrivateKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly Ed448PrivateKeyParameters m_ed448Key;
        private readonly MLDsaPrivateKeyParameters m_mlDsaKey;

        /// <summary>Generate a new composite private key, with the two components generated independently.</summary>
        /// <param name="random">The source of randomness.</param>
        public MLDsa87Ed448PrivateKeyParameters(SecureRandom random)
            : base(privateKey: true)
        {
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            m_ed448Key = new Ed448PrivateKeyParameters(random);

            var mlDsaGenerator = new MLDsaKeyPairGenerator();
            mlDsaGenerator.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_87));
            m_mlDsaKey = (MLDsaPrivateKeyParameters)mlDsaGenerator.GenerateKeyPair().Private;
        }

        /// <summary>Create a composite private key from its two components.</summary>
        /// <param name="ed448Key">The Ed448 component.</param>
        /// <param name="mlDsaKey">The ML-DSA component, which must use the ML-DSA-87 parameter set and have its seed
        /// available.</param>
        public MLDsa87Ed448PrivateKeyParameters(Ed448PrivateKeyParameters ed448Key,
            MLDsaPrivateKeyParameters mlDsaKey)
            : base(privateKey: true)
        {
            m_ed448Key = ed448Key ?? throw new ArgumentNullException(nameof(ed448Key));
            m_mlDsaKey = mlDsaKey ?? throw new ArgumentNullException(nameof(mlDsaKey));

            if (mlDsaKey.Parameters != MLDsaParameters.ml_dsa_87)
                throw new ArgumentException("ML-DSA key must use ML-DSA-87", nameof(mlDsaKey));
            if (mlDsaKey.GetSeed() == null)
                throw new ArgumentException("ML-DSA key must have a seed", nameof(mlDsaKey));
        }

        /// <summary>The Ed448 component.</summary>
        public Ed448PrivateKeyParameters Ed448Key => m_ed448Key;

        /// <summary>The ML-DSA-87 component.</summary>
        public MLDsaPrivateKeyParameters MLDsaKey => m_mlDsaKey;

        /// <summary>Derive the corresponding composite public key.</summary>
        public MLDsa87Ed448PublicKeyParameters GeneratePublicKey() =>
            new MLDsa87Ed448PublicKeyParameters(m_ed448Key.GeneratePublicKey(), m_mlDsaKey.GetPublicKey());
    }
}
