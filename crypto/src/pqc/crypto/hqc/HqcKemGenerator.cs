using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public class HqcKemGenerator : IEncapsulatedSecretGenerator
    {
        private SecureRandom sr;
        public HqcKemGenerator(SecureRandom random)
        {
            sr = random;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            HqcPublicKeyParameters key = (HqcPublicKeyParameters)recipientKey;
            HqcEngine engine = key.Parameters.Engine;

            byte[] K = new byte[key.Parameters.Sha512Bytes];
            byte[] u = new byte[key.Parameters.NBytes];
            byte[] v = new byte[key.Parameters.N1n2Bytes];
            byte[] d = new byte[key.Parameters.Sha512Bytes];
            byte[] salt = new byte[key.Parameters.SaltSizeBytes];
            byte[] pk = key.PublicKey;
            byte[] seed = new byte[48];

            sr.NextBytes(seed);

            engine.Encaps(u, v, K, d, pk, seed, salt);

            byte[] cipherText = Arrays.ConcatenateAll(u, v, d, salt);

            return new SecretWithEncapsulationImpl(K, cipherText);
        }

        private class SecretWithEncapsulationImpl : ISecretWithEncapsulation
        {
            private volatile bool hasBeenDestroyed;

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
