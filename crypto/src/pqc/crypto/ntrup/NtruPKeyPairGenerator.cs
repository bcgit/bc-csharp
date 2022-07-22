using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.pqc.crypto.NtruP
{
    public class NtruKeyPairGenerator
    {
        private NtruKeyGenerationParameters ntruParams;

        private int p;
        private int q;

        private SecureRandom random;

        private void Initialize(KeyGenerationParameters param)
        {
            ntruParams = (NtruKeyGenerationParameters) param;
            random = param.Random;

            // n = ntruParams.Parameters.N;

            p = ntruParams.PParameters.P;
            q = ntruParams.PParameters.Q;

        }

        private AsymmetricCipherKeyPair GenKeyPair()
        {
            NtruPEngine pEngine = ntruParams.PParameters.PEngine;
            byte[] sk = new byte[pEngine.PrivateKeySize];
            byte[] pk = new byte[pEngine.PublicKeySize];
            pEngine.kem_keypair( pk,sk,random);

            NtruPPublicKeyParameters pubKey = new NtruPPublicKeyParameters(ntruParams.PParameters, pk);
            NtruPPrivateKeyParameters privKey = new NtruPPrivateKeyParameters(ntruParams.PParameters, sk);
            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }
        
        public void Init(KeyGenerationParameters param)
        {
            this.Initialize(param);
        }
        
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenKeyPair();
        }
        
        // private AsymmetricCipherKeyPair GenKeyPair()
        // {
        //     NtruEngine engine = ntruParams.Parameters.Engine;
        //     byte[] sk = new byte[engine.PrivateKeySize];
        //     byte[] pk = new byte[engine.PublicKeySize];
        //     
        //     
        // }
        //
        // public void Init(KeyGenerationParameters param)
        // {
        //     this.Initialize(param);
        // }
        //
        // public AsymmetricCipherKeyPair GenerateKeyPair()
        // {
        //     return GenKeyPair();
        // }

    }
}