using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.MLKem;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
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
            MLKemExtractor kemExtract = new MLKemExtractor(privateKey);
            byte[] secret = kemExtract.ExtractSecret(ciphertext);
            return m_crypto.AdoptLocalSecret(secret);
        }

        public virtual MLKemPublicKeyParameters DecodePublicKey(byte[] encoding)
        {
            return new MLKemPublicKeyParameters(m_domainParameters, encoding);
        }

        public virtual byte[] Encapsulate(MLKemPublicKeyParameters publicKey, out TlsSecret secret)
        {
            MLKemGenerator kemGen = new MLKemGenerator(m_crypto.SecureRandom);
            ISecretWithEncapsulation encapsulated = kemGen.GenerateEncapsulated(publicKey);
            secret = m_crypto.AdoptLocalSecret(encapsulated.GetSecret());
            return encapsulated.GetEncapsulation();
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
