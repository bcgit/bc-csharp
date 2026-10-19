using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public class SNtruPrimeKemGenerator : IEncapsulatedSecretGenerator
    {
        private SecureRandom sr;

        /// <summary>Create a new <see cref="SNtruPrimeKemGenerator"/>.</summary>
        /// <param name="sr">The sr.</param>
        public SNtruPrimeKemGenerator(SecureRandom sr)
        {
            this.sr = sr;
        }

        /// <inheritdoc/>
        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            SNtruPrimePublicKeyParameters key = (SNtruPrimePublicKeyParameters)recipientKey;
            NtruPrimeEngine primeEngine = key.Parameters.PrimeEngine;
            byte[] cipherText = new byte[primeEngine.CipherTextSize];
            byte[] sessionKey = new byte[primeEngine.SessionKeySize];
            primeEngine.kem_enc(cipherText, sessionKey,key.pubKey, sr);
            return new NtruLPRimeKemGenerator.SecretWithEncapsulationImpl(sessionKey, cipherText);
        }

        // TODO[api] private sealed
        public class SecretWithEncapsulationImpl : ISecretWithEncapsulation
        {
            private volatile bool hasBeenDestroyed = false;

            private byte[] sessionKey;
            private byte[] cipherText;

            /// <summary>Create a new <see cref="SecretWithEncapsulationImpl"/>.</summary>
            /// <param name="sessionKey">The session key.</param>
            /// <param name="cipherText">The cipher text.</param>
            public SecretWithEncapsulationImpl(byte[] sessionKey, byte[] cipherText)
            {
                this.sessionKey = sessionKey;
                this.cipherText = cipherText;
            }

            /// <inheritdoc/>
            public byte[] GetSecret()
            {
                CheckDestroyed();
                return Arrays.Clone(sessionKey);
            }

            /// <inheritdoc/>
            public byte[] GetEncapsulation()
            {
                return Arrays.Clone(cipherText);
            }

            public void Dispose()
            {
                Dispose(disposing: true);
                GC.SuppressFinalize(this);
            }

            protected virtual void Dispose(bool disposing)
            {
                if (disposing)
                {
                    if (!hasBeenDestroyed)
                    {
                        Arrays.Clear(sessionKey);
                        Arrays.Clear(cipherText);
                        hasBeenDestroyed = true;
                    }
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
