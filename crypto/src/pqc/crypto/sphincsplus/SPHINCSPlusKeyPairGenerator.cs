
using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    public sealed class SphincsPlusKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom random;
        private SphincsPlusParameters parameters;

        public void Init(KeyGenerationParameters param)
        {
            random = param.Random;
            parameters = ((SphincsPlusKeyGenerationParameters)param).Parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            SphincsPlusEngine engine = parameters.GetEngine();
            byte[] pkSeed;
            SK sk;

            if (engine is SphincsPlusEngine.HarakaSEngine
#if NETCOREAPP3_0_OR_GREATER
                || engine is SphincsPlusEngine.HarakaSEngine_X86
#endif
                )
            {
                // required to pass kat tests
                byte[] tmparray = SecRand(engine.N * 3);
                byte[] skseed = new byte[engine.N];
                byte[] skprf = new byte[engine.N];
                pkSeed = new byte[engine.N];
                Array.Copy(tmparray, 0, skseed, 0, engine.N);
                Array.Copy(tmparray, engine.N, skprf, 0, engine.N);
                Array.Copy(tmparray, engine.N << 1, pkSeed, 0, engine.N);
                sk = new SK(skseed, skprf);
            }
            else
            {
                sk = new SK(SecRand(engine.N), SecRand(engine.N));
                pkSeed = SecRand(engine.N);
            }
            engine.Init(pkSeed);
            // TODO
            PK pk = new PK(pkSeed, new HT(engine, sk.seed, pkSeed).HTPubKey);

            return new AsymmetricCipherKeyPair(new SphincsPlusPublicKeyParameters(parameters, pk),
                new SphincsPlusPrivateKeyParameters(parameters, sk, pk));
        }

        private byte[] SecRand(int n)
        {
            return SecureRandom.GetNextBytes(random, n);
        }
    }
}
