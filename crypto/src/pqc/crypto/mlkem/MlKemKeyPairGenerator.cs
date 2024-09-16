using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public class MLKemKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private MLKemParameters mlkemParams;

        private SecureRandom random;

        public void Init(KeyGenerationParameters param)
        {
            this.mlkemParams = ((MLKemKeyGenerationParameters)param).Parameters;
            this.random = param.Random;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            MLKemEngine engine = mlkemParams.Engine;
            engine.Init(random);
            engine.GenerateKemKeyPair(out byte[] t, out byte[] rho, out byte[] s, out byte[] hpk, out byte[] nonce);

            MLKemPublicKeyParameters pubKey = new MLKemPublicKeyParameters(mlkemParams, t, rho);
            MLKemPrivateKeyParameters privKey = new MLKemPrivateKeyParameters(mlkemParams, s, hpk, nonce, t, rho);
            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }

        // FIXME Avoid needing this in the public API
        public AsymmetricCipherKeyPair InternalGenerateKeyPair(byte[] d, byte[] z)
        {
            byte[][] keyPair = mlkemParams.Engine.GenerateKemKeyPairInternal(d, z);
            MLKemPublicKeyParameters pubKey = new MLKemPublicKeyParameters(mlkemParams, keyPair[0], keyPair[1]);
            MLKemPrivateKeyParameters privKey = new MLKemPrivateKeyParameters(mlkemParams, keyPair[2], keyPair[3], keyPair[4], keyPair[0], keyPair[1]);
            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }
    }
}