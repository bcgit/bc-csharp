using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Private key for the OpenPGP ML-KEM-1024+X448 composite KEM
    /// (<see cref="PublicKeyAlgorithmTag.MLKem1024_X448"/>).
    /// </summary>
    /// <remarks>
    /// OpenPGP stores the ML-KEM secret key in seed format (RFC 9980 4.3.2.2), so the ML-KEM component must have a
    /// seed available.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4.2">
    /// Post-Quantum Cryptography in OpenPGP - Composite Encryption Schemes with ML-KEM
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLKem1024X448PrivateKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly X448PrivateKeyParameters m_x448Key;
        private readonly MLKemPrivateKeyParameters m_mlKemKey;

        /// <summary>Generate a new composite private key, with the two components generated independently.</summary>
        /// <param name="random">The source of randomness.</param>
        public MLKem1024X448PrivateKeyParameters(SecureRandom random)
            : base(privateKey: true)
        {
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            m_x448Key = new X448PrivateKeyParameters(random);

            var mlKemGenerator = new MLKemKeyPairGenerator();
            mlKemGenerator.Init(new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_1024));
            m_mlKemKey = (MLKemPrivateKeyParameters)mlKemGenerator.GenerateKeyPair().Private;
        }

        /// <summary>Create a composite private key from its two components.</summary>
        /// <param name="x448Key">The X448 component.</param>
        /// <param name="mlKemKey">The ML-KEM component, which must use the ML-KEM-1024 parameter set and have its seed
        /// available.</param>
        public MLKem1024X448PrivateKeyParameters(X448PrivateKeyParameters x448Key,
            MLKemPrivateKeyParameters mlKemKey)
            : base(privateKey: true)
        {
            m_x448Key = x448Key ?? throw new ArgumentNullException(nameof(x448Key));
            m_mlKemKey = mlKemKey ?? throw new ArgumentNullException(nameof(mlKemKey));

            if (mlKemKey.Parameters != MLKemParameters.ml_kem_1024)
                throw new ArgumentException("ML-KEM key must use ML-KEM-1024", nameof(mlKemKey));
            if (mlKemKey.GetSeed() == null)
                throw new ArgumentException("ML-KEM key must have a seed", nameof(mlKemKey));
        }

        /// <summary>The X448 component.</summary>
        public X448PrivateKeyParameters X448Key => m_x448Key;

        /// <summary>The ML-KEM-1024 component.</summary>
        public MLKemPrivateKeyParameters MLKemKey => m_mlKemKey;

        /// <summary>Derive the corresponding composite public key.</summary>
        public MLKem1024X448PublicKeyParameters GeneratePublicKey() =>
            new MLKem1024X448PublicKeyParameters(m_x448Key.GeneratePublicKey(), m_mlKemKey.GetPublicKey());
    }
}
