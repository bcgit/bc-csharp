using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public sealed class BikeKemGenerator
        : IEncapsulatedSecretGenerator
    {
        private readonly SecureRandom sr;

        public BikeKemGenerator(SecureRandom random)
        {
            this.sr = random;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            BikePublicKeyParameters key = (BikePublicKeyParameters)recipientKey;
            BikeParameters parameters = key.Parameters;
            BikeEngine engine = parameters.BikeEngine;

            byte[] K = new byte[parameters.LByte];
            byte[] c01 = new byte[parameters.RByte + parameters.LByte];
            byte[] h = key.PublicKey;

            engine.Encaps(c01, K, h, sr);

            return new SecretWithEncapsulationImpl(Arrays.CopyOfRange(K, 0, parameters.DefaultKeySize / 8), c01);
        }

        private sealed class SecretWithEncapsulationImpl
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
                    Arrays.Clear(sessionKey);
                    Arrays.Clear(cipher_text);
                    hasBeenDestroyed = true;
                }
                GC.SuppressFinalize(this);
            }

            public bool IsDestroyed()
            {
                return hasBeenDestroyed;
            }

            void CheckDestroyed()
            {
                if (IsDestroyed())
                    throw new Exception("data has been destroyed");
            }
        }
    }
}
