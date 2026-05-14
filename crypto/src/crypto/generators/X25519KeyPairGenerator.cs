using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    /// <summary>
    /// Key-pair generator for X25519 (RFC 7748). Only the <see cref="SecureRandom"/> from the supplied
    /// <see cref="KeyGenerationParameters"/> is used; the 32-byte clamped scalar is drawn directly from it.
    /// </summary>
    public class X25519KeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom random;

        /// <summary>Capture the <see cref="SecureRandom"/> that will source the scalar.</summary>
        public virtual void Init(KeyGenerationParameters parameters)
        {
            this.random = parameters.Random;
        }

        /// <summary>Generate a fresh X25519 key pair.</summary>
        public virtual AsymmetricCipherKeyPair GenerateKeyPair()
        {
            X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(random);
            X25519PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
    }
}
