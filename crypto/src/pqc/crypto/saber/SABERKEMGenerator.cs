using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public sealed class SaberKemGenerator
        : IEncapsulatedSecretGenerator
    {
        // the source of randomness
        private SecureRandom sr;

        public SaberKemGenerator(SecureRandom random)
        {
            this.sr = CryptoServicesRegistrar.GetSecureRandom(random);
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            SaberPublicKeyParameters key = (SaberPublicKeyParameters)recipientKey;
            SaberEngine engine = key.Parameters.Engine;
            byte[] cipher_text = new byte[engine.GetCipherTextSize()];
            byte[] sessionKey = new byte[engine.GetSessionKeySize()];
            engine.crypto_kem_enc(cipher_text, sessionKey, key.GetPublicKey(), sr);
            return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
        }
    }
}
