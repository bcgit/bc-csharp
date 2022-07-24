using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public class NtruPrimeKemGenerator : IEncapsulatedSecretGenerator
    {
        private SecureRandom sr;
        
        public NtruPrimeKemGenerator(SecureRandom sr)
        {
            this.sr = sr;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            NtruPrimePublicKeyParameters key = (NtruPrimePublicKeyParameters)recipientKey;
            NtruPrimeEngine pEngine = key.Parameters.PEngine;
            byte[] cipherText = new byte[pEngine.CipherTextSize];
            byte[] sessionKey = new byte[pEngine.SessionKeySize];
            pEngine.kem_enc(cipherText, sessionKey,key.pubKey, sr);
            return new NtruPrimeKemGenerator.SecretWithEncapsulationImpl(sessionKey, cipherText);
        }

        public class SecretWithEncapsulationImpl : ISecretWithEncapsulation
        {
            private volatile bool hasBeenDestroyed = false;
            
            private byte[] sessionKey;
            private byte[] cipherText;
            
            public SecretWithEncapsulationImpl(byte[] sessionKey, byte[] cipherText)
            {
                this.sessionKey = sessionKey;
                this.cipherText = cipherText;
            }

            public byte[] GetSecret()
            {
                CheckDestroyed();
                return Arrays.Clone(sessionKey);
            }

            public byte[] GetEncapsulation()
            {
                return Arrays.Clone(cipherText);
            }

            public void Dispose()
            {
                if (!hasBeenDestroyed)
                {
                    hasBeenDestroyed = true;
                    Arrays.Clear(sessionKey);
                    Arrays.Clear(cipherText);
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
