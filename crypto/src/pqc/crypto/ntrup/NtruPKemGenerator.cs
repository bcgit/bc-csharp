using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.pqc.crypto.NtruP
{
    public class NtruPKemGenerator : IEncapsulatedSecretGenerator
    {
        private SecureRandom sr;
        
        public NtruPKemGenerator(SecureRandom sr)
        {
            this.sr = sr;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            NtruPPublicKeyParameters key = (NtruPPublicKeyParameters)recipientKey;
            NtruPEngine pEngine = key.PParameters.PEngine;
            byte[] cipherText = new byte[pEngine.CipherTextSize];
            byte[] sessionKey = new byte[pEngine.SessionKeySize];
            pEngine.kem_enc(cipherText, sessionKey,key.PublicKey, sr);
            return new NtruPKemGenerator.SecretWithEncapsulationImpl(sessionKey, cipherText);
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