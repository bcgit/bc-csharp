using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    public class DilithiumKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator

    {
        private SecureRandom random;
        private DilithiumParameters parameters;

        public void Init(KeyGenerationParameters param)
        {
            random = param.Random;
            parameters = ((DilithiumKeyGenerationParameters)param).Parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            DilithiumEngine engine = parameters.GetEngine(random);
            byte[] rho, key, tr, s1, s2, t0, encT1;
            engine.GenerateKeyPair(out rho, out key, out tr, out s1, out s2, out t0, out encT1);
            
            //unpack sk

            DilithiumPublicKeyParameters pubKey = new DilithiumPublicKeyParameters(parameters, rho, encT1);
            DilithiumPrivateKeyParameters privKey = new DilithiumPrivateKeyParameters(parameters, rho, key, tr, s1, s2, t0, encT1);


            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }
    }
}