using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    public sealed class SlhDsaKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom m_random;
        private SlhDsaParameters m_parameters;

        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
            m_parameters = ((SlhDsaKeyGenerationParameters)parameters).Parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var engine = m_parameters.GetEngine();

            byte[] skSeed = SecRand(engine.N);
            byte[] skPrf = SecRand(engine.N);
            byte[] pkSeed = SecRand(engine.N);

            SK sk = new SK(skSeed, skPrf);

            engine.Init(pkSeed);

            // TODO
            PK pk = new PK(pkSeed, new HT(engine, sk.seed, pkSeed).HTPubKey);

            return new AsymmetricCipherKeyPair(
                new SlhDsaPublicKeyParameters(m_parameters, pk),
                new SlhDsaPrivateKeyParameters(m_parameters, sk, pk));
        }

        private byte[] SecRand(int n) => SecureRandom.GetNextBytes(m_random, n);
    }
}
