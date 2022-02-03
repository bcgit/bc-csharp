
using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public class SABERKEMGenerator
        : IEncapsulatedSecretGenerator
    {
        // the source of randomness
        private SecureRandom sr;

        public SABERKEMGenerator(SecureRandom random)
        {
            this.sr = random;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            SABERPublicKeyParameters key = (SABERPublicKeyParameters) recipientKey;
            SABEREngine engine = key.GetParameters().GetEngine();
            byte[] cipher_text = new byte[engine.GetCipherTextSize()];
            byte[] sessionKey = new byte[engine.GetSessionKeySize()];
            engine.crypto_kem_enc(cipher_text, sessionKey, key.PublicKey, sr);
            return new SABERKEMGenerator.SecretWithEncapsulationImpl(sessionKey, cipher_text);
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
                    throw new ArgumentException("data has been destroyed");
                }
            }
        }
    }
}