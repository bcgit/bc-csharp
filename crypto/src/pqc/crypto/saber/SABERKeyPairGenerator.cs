using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    /// <summary>A generator of SABER key pairs.</summary>
    public class SaberKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SaberKeyGenerationParameters saberParams;

        private int l;

        private SecureRandom random;

        private void Initialize(
            KeyGenerationParameters param)
        {
            this.saberParams = (SaberKeyGenerationParameters)param;
            this.random = param.Random;

            this.l = this.saberParams.Parameters.L;
        }

        private AsymmetricCipherKeyPair GenKeyPair()
        {
            SaberEngine engine = saberParams.Parameters.Engine;
            byte[] sk = new byte[engine.GetPrivateKeySize()];
            byte[] pk = new byte[engine.GetPublicKeySize()];
            engine.crypto_kem_keypair(pk, sk, random);

            SaberPublicKeyParameters pubKey = new SaberPublicKeyParameters(saberParams.Parameters, pk);
            SaberPrivateKeyParameters privKey = new SaberPrivateKeyParameters(saberParams.Parameters, sk);
            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }

        /// <inheritdoc/>
        public void Init(KeyGenerationParameters param)
        {
            this.Initialize(param);
        }

        /// <inheritdoc/>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenKeyPair();
        }
    }
}
