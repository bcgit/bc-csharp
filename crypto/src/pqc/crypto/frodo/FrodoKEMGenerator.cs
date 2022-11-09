using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    public class FrodoKEMGenerator
        : IEncapsulatedSecretGenerator
    {
        // the source of randomness
        private readonly SecureRandom sr;

        public FrodoKEMGenerator(SecureRandom random)
        {
            this.sr = random;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            FrodoPublicKeyParameters key = (FrodoPublicKeyParameters) recipientKey;
            FrodoEngine engine = key.Parameters.Engine;
            byte[] cipher_text = new byte[engine.CipherTextSize];
            byte[] sessionKey = new byte[engine.SessionKeySize];
            engine.kem_enc(cipher_text, sessionKey, key.m_publicKey, sr);
            return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
        }
    }
}
