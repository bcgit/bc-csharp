
using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    public class FrodoKEMGenerator
        : IEncapsulatedSecretGenerator
    {
        // the source of randomness
        private SecureRandom sr;

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
            engine.kem_enc(cipher_text, sessionKey, key.PublicKey, sr);
            return new FrodoKEMGenerator.SecretWithEncapsulationImpl(sessionKey, cipher_text);
        }

        private class SecretWithEncapsulationImpl
            : ISecretWithEncapsulation
        {

            private volatile bool hasBeenDestroyed = false;

            private byte[] sessionKey;
            private byte[] cipher_text;

            public SecretWithEncapsulationImpl(byte[] sessionKey, byte[] cipher_text)
            {
                this.sessionKey = sessionKey;
                this.cipher_text = cipher_text;
            }

            public byte[] GetSecret()
            {
                CheckDestroyed();

                return Arrays.Clone(sessionKey);
            }

            public byte[] GetEncapsulation()
            {
                CheckDestroyed();

                return Arrays.Clone(cipher_text);
            }

            public void Dispose()
            {
                if (!hasBeenDestroyed)
                {
                    hasBeenDestroyed = true;
                    Arrays.Clear(sessionKey);
                    Arrays.Clear(cipher_text);
                }
            }

            public bool IsDestroyed()
            {
                return hasBeenDestroyed;
            }

            void CheckDestroyed()
            {
                if (IsDestroyed())
                {
                    throw new Exception("data has been destroyed");
                }
            }
        }
    }
}
