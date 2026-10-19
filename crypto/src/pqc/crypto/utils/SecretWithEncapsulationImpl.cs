using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Utilities
{
    /// <summary>A shared secret together with its encapsulation.</summary>
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

        /// <summary>Destroy the secret.</summary>
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        /// <summary>Destroy the secret.</summary>
        /// <param name="disposing">true when called from <c>Dispose</c>, false when called from a finalizer.</param>
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

        /// <summary>Determine whether the secret has been destroyed.</summary>
        /// <returns>true if it has been destroyed, false otherwise.</returns>
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
