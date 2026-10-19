using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Utilities
{
    public class SecretWithEncapsulationImpl
        : ISecretWithEncapsulation
    {
        private volatile bool hasBeenDestroyed = false;

        private byte[] sessionKey;
        private byte[] cipher_text;

        /// <summary>Create a new <see cref="SecretWithEncapsulationImpl"/>.</summary>
        /// <param name="sessionKey">The session key.</param>
        /// <param name="cipher_text">The cipher text.</param>
        public SecretWithEncapsulationImpl(byte[] sessionKey, byte[] cipher_text)
        {
            this.sessionKey = sessionKey;
            this.cipher_text = cipher_text;
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
            CheckDestroyed();

            return Arrays.Clone(cipher_text);
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
                    Arrays.Clear(cipher_text);
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
