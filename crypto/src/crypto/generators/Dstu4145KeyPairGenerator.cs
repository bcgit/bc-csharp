using System;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Generators
{
    // TODO[api] Could just subclass ECKeyPairGenerator except that GenerateKeyPair is not marked virtual there
    public class Dstu4145KeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private readonly ECKeyPairGenerator m_inner = new ECKeyPairGenerator();

        public virtual void Init(KeyGenerationParameters parameters) => m_inner.Init(parameters);

        public virtual AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var keyPair = m_inner.GenerateKeyPair();

            var publicKey = (ECPublicKeyParameters)keyPair.Public;
            var privateKey = (ECPrivateKeyParameters)keyPair.Private;

            publicKey = new ECPublicKeyParameters(publicKey.AlgorithmName, publicKey.Q.Negate(), publicKey.Parameters);

            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
    }
}
