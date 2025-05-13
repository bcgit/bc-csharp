using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    // TODO[api] Make sealed
    public class BcTlsMLKemDomain
        : TlsKemDomain
    {
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

        protected readonly BcTlsCrypto m_crypto;
        // TODO[api] Remove
        protected readonly TlsKemConfig m_config;
        protected readonly MLKemParameters m_domainParameters;
        protected readonly bool m_isServer;

        public BcTlsMLKemDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
        {
            m_crypto = crypto;
            m_config = kemConfig;
            m_domainParameters = GetDomainParameters(kemConfig);
            m_isServer = kemConfig.IsServer;
        }

        public virtual TlsAgreement CreateKem()
        {
            return new BcTlsMLKem(this);
        }

        public virtual BcTlsSecret Decapsulate(MLKemPrivateKeyParameters privateKey, byte[] ciphertext)
        {
            var decapsulator = KemUtilities.GetDecapsulator(m_domainParameters.Oid);
            decapsulator.Init(privateKey);
            var sec = KemUtilities.Decapsulate(decapsulator, ciphertext, 0, ciphertext.Length);
            return m_crypto.AdoptLocalSecret(sec);
        }

        public virtual MLKemPublicKeyParameters DecodePublicKey(byte[] encoding) =>
            MLKemPublicKeyParameters.FromEncoding(m_domainParameters, encoding);

        public virtual byte[] Encapsulate(MLKemPublicKeyParameters publicKey, out TlsSecret secret)
        {
            var encapsulator = KemUtilities.GetEncapsulator(m_domainParameters.Oid);
            encapsulator.Init(new ParametersWithRandom(publicKey, m_crypto.SecureRandom));
            var enc_sec = KemUtilities.Encapsulate(encapsulator);
            secret = m_crypto.AdoptLocalSecret(enc_sec.Item2);
            return enc_sec.Item1;
        }

        public virtual byte[] EncodePublicKey(MLKemPublicKeyParameters publicKey)
        {
            return publicKey.GetEncoded();
        }

        public virtual AsymmetricCipherKeyPair GenerateKeyPair()
        {
            MLKemKeyPairGenerator keyPairGenerator = new MLKemKeyPairGenerator();
            keyPairGenerator.Init(new MLKemKeyGenerationParameters(m_crypto.SecureRandom, m_domainParameters));
            return keyPairGenerator.GenerateKeyPair();
        }

        public virtual bool IsServer => m_isServer;
    }
}
