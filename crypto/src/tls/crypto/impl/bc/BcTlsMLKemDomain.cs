using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>The ML-KEM domain for TLS, using the Bouncy Castle implementation.</summary>
    // TODO[api] Make sealed
    public class BcTlsMLKemDomain
        : TlsKemDomain
    {
        /// <summary>Get the ML-KEM parameters for a KEM configuration.</summary>
        /// <param name="kemConfig">The configuration.</param>
        /// <returns>The parameters.</returns>
        public static MLKemParameters GetDomainParameters(TlsKemConfig kemConfig)
        {
            switch (kemConfig.NamedGroup)
            {
            case NamedGroup.MLKEM512:
                return MLKemParameters.ml_kem_512;
            case NamedGroup.MLKEM768:
                return MLKemParameters.ml_kem_768;
            case NamedGroup.MLKEM1024:
                return MLKemParameters.ml_kem_1024;
            default:
                throw new ArgumentException("No ML-KEM configuration provided", nameof(kemConfig));
            }
        }

        /// <summary>The crypto.</summary>
        protected readonly BcTlsCrypto m_crypto;
        /// <summary>The config.</summary>
        // TODO[api] Remove
        protected readonly TlsKemConfig m_config;
        /// <summary>The domain parameters.</summary>
        protected readonly MLKemParameters m_domainParameters;
        /// <summary>The is server.</summary>
        protected readonly bool m_isServer;

        /// <summary>Create a new <see cref="BcTlsMLKemDomain"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="kemConfig">The kem config.</param>
        public BcTlsMLKemDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
        {
            m_crypto = crypto;
            m_config = kemConfig;
            m_domainParameters = GetDomainParameters(kemConfig);
            m_isServer = kemConfig.IsServer;
        }

        /// <inheritdoc/>
        public virtual TlsAgreement CreateKem()
        {
            return new BcTlsMLKem(this);
        }

        /// <summary>Decapsulate a shared secret.</summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <returns>The shared secret.</returns>
        public virtual BcTlsSecret Decapsulate(MLKemPrivateKeyParameters privateKey, byte[] ciphertext)
        {
            var decapsulator = KemUtilities.GetDecapsulator(m_domainParameters.Oid);
            decapsulator.Init(privateKey);
            var sec = KemUtilities.Decapsulate(decapsulator, ciphertext, 0, ciphertext.Length);
            return m_crypto.AdoptLocalSecret(sec);
        }

        /// <summary>Decode an ML-KEM public key.</summary>
        /// <param name="encoding">The encoding.</param>
        /// <returns>The public key.</returns>
        public virtual MLKemPublicKeyParameters DecodePublicKey(byte[] encoding) =>
            MLKemPublicKeyParameters.FromEncoding(m_domainParameters, encoding);

        /// <summary>Encapsulate a shared secret.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="secret">On return, the shared secret.</param>
        /// <returns>The ciphertext.</returns>
        public virtual byte[] Encapsulate(MLKemPublicKeyParameters publicKey, out TlsSecret secret)
        {
            var encapsulator = KemUtilities.GetEncapsulator(m_domainParameters.Oid);
            encapsulator.Init(new ParametersWithRandom(publicKey, m_crypto.SecureRandom));
            var enc_sec = KemUtilities.Encapsulate(encapsulator);
            secret = m_crypto.AdoptLocalSecret(enc_sec.Item2);
            return enc_sec.Item1;
        }

        /// <summary>Encode an ML-KEM public key.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <returns>The encoding.</returns>
        public virtual byte[] EncodePublicKey(MLKemPublicKeyParameters publicKey)
        {
            return publicKey.GetEncoded();
        }

        /// <summary>Generate an ML-KEM key pair.</summary>
        /// <returns>The key pair.</returns>
        public virtual AsymmetricCipherKeyPair GenerateKeyPair()
        {
            MLKemKeyPairGenerator keyPairGenerator = new MLKemKeyPairGenerator();
            keyPairGenerator.Init(new MLKemKeyGenerationParameters(m_crypto.SecureRandom, m_domainParameters));
            return keyPairGenerator.GenerateKeyPair();
        }

        /// <summary>Gets a value indicating whether this is server.</summary>
        public virtual bool IsServer => m_isServer;
    }
}
