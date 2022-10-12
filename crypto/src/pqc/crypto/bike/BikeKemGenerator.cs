using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public class BikeKemGenerator : IEncapsulatedSecretGenerator
    {
        private SecureRandom sr;
        public BikeKemGenerator(SecureRandom random)
        {
            this.sr = random;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            BikePublicKeyParameters key = (BikePublicKeyParameters)recipientKey;
            BikeEngine engine = key.Parameters.BIKEEngine;

            byte[] K = new byte[key.Parameters.LByte];
            byte[] c0 = new byte[key.Parameters.RByte];
            byte[] c1 = new byte[key.Parameters.LByte];
            byte[] h = key.PublicKey;

            engine.Encaps(c0, c1, K, h, sr);

            byte[] cipherText = Arrays.Concatenate(c0, c1);

            return new SecretWithEncapsulationImpl(Arrays.CopyOfRange(K, 0, key.Parameters.DefaultKeySize / 8), cipherText);
        }

        private class SecretWithEncapsulationImpl : ISecretWithEncapsulation
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
