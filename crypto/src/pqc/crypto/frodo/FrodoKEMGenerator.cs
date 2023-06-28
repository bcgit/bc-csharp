using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    // TODO[api] FrodoKemGenerator
    public class FrodoKEMGenerator
        : IEncapsulatedSecretGenerator
    {
        // the source of randomness
        private readonly SecureRandom m_random;

        public FrodoKEMGenerator(SecureRandom random)
        {
            m_random = random;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            FrodoPublicKeyParameters key = (FrodoPublicKeyParameters)recipientKey;
#pragma warning disable CS0618 // Type or member is obsolete
            FrodoEngine engine = key.Parameters.Engine;
#pragma warning restore CS0618 // Type or member is obsolete
            byte[] cipher_text = new byte[engine.CipherTextSize];
            byte[] sessionKey = new byte[engine.SessionKeySize];
            engine.kem_enc(cipher_text, sessionKey, key.m_publicKey, m_random);
            return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
        }
    }
}
