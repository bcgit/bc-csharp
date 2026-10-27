using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    /// <summary>A generator of NTRU LPRime key pairs.</summary>
    public class NtruLPRimeKeyPairGenerator
    {
        private NtruLPRimeKeyGenerationParameters _ntruPrimeParams;

        private int p;
        private int q;

        private SecureRandom random;

        private void Initialize(KeyGenerationParameters param)
        {
            _ntruPrimeParams = (NtruLPRimeKeyGenerationParameters) param;
            random = param.Random;

            // n = ntruParams.Parameters.N;

            p = _ntruPrimeParams.Parameters.P;
            q = _ntruPrimeParams.Parameters.Q;

        }

        private AsymmetricCipherKeyPair GenKeyPair()
        {
            NtruPrimeEngine primeEngine = _ntruPrimeParams.Parameters.PrimeEngine;
            byte[] sk = new byte[primeEngine.PrivateKeySize];
            byte[] pk = new byte[primeEngine.PublicKeySize];
            primeEngine.kem_keypair( pk,sk,random);

            NtruLPRimePublicKeyParameters pubKey = new NtruLPRimePublicKeyParameters(_ntruPrimeParams.Parameters, pk);
            NtruLPRimePrivateKeyParameters privKey = new NtruLPRimePrivateKeyParameters(_ntruPrimeParams.Parameters, sk);
            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }

        /// <summary>Initialise the generator.</summary>
        /// <param name="param">The key generation parameters.</param>
        public void Init(KeyGenerationParameters param)
        {
            this.Initialize(param);
        }

        /// <summary>Generate a key pair.</summary>
        /// <returns>The key pair.</returns>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenKeyPair();
        }
    }
}
