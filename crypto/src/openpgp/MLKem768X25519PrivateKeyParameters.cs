using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Private key for the OpenPGP ML-KEM-768+X25519 composite KEM
    /// (<see cref="PublicKeyAlgorithmTag.MLKem768_X25519"/>).
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
    public sealed class MLKem768X25519PrivateKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly X25519PrivateKeyParameters m_x25519Key;
        private readonly MLKemPrivateKeyParameters m_mlKemKey;

        /// <summary>Generate a new composite private key, with the two components generated independently.</summary>
        /// <param name="random">The source of randomness.</param>
        public MLKem768X25519PrivateKeyParameters(SecureRandom random)
            : base(privateKey: true)
        {
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            m_x25519Key = new X25519PrivateKeyParameters(random);

            var mlKemGenerator = new MLKemKeyPairGenerator();
            mlKemGenerator.Init(new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768));
            m_mlKemKey = (MLKemPrivateKeyParameters)mlKemGenerator.GenerateKeyPair().Private;
        }

        /// <summary>Create a composite private key from its two components.</summary>
        /// <param name="x25519Key">The X25519 component.</param>
        /// <param name="mlKemKey">The ML-KEM component, which must use the ML-KEM-768 parameter set and have its seed
        /// available.</param>
        public MLKem768X25519PrivateKeyParameters(X25519PrivateKeyParameters x25519Key,
            MLKemPrivateKeyParameters mlKemKey)
            : base(privateKey: true)
        {
            m_x25519Key = x25519Key ?? throw new ArgumentNullException(nameof(x25519Key));
            m_mlKemKey = mlKemKey ?? throw new ArgumentNullException(nameof(mlKemKey));

            if (mlKemKey.Parameters != MLKemParameters.ml_kem_768)
                throw new ArgumentException("ML-KEM key must use ML-KEM-768", nameof(mlKemKey));
            if (mlKemKey.GetSeed() == null)
                throw new ArgumentException("ML-KEM key must have a seed", nameof(mlKemKey));
        }

        /// <summary>The X25519 component.</summary>
        public X25519PrivateKeyParameters X25519Key => m_x25519Key;

        /// <summary>The ML-KEM-768 component.</summary>
        public MLKemPrivateKeyParameters MLKemKey => m_mlKemKey;

        /// <summary>Derive the corresponding composite public key.</summary>
        public MLKem768X25519PublicKeyParameters GeneratePublicKey() =>
            new MLKem768X25519PublicKeyParameters(m_x25519Key.GeneratePublicKey(), m_mlKemKey.GetPublicKey());
    }
}
