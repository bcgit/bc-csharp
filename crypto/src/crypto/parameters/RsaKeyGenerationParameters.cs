using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for generating RSA key pairs.</summary>
    public class RsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly BigInteger publicExponent;
        private readonly int certainty;

        /// <summary>Create a new <see cref="RsaKeyGenerationParameters"/>.</summary>
        /// <param name="publicExponent">The public exponent.</param>
        /// <param name="random">The source of randomness.</param>
        /// <param name="strength">The security strength in bits.</param>
        /// <param name="certainty">The certainty.</param>
        public RsaKeyGenerationParameters(
            BigInteger publicExponent,
            SecureRandom random,
            int strength,
            int certainty)
            : base(random, strength)
        {
            this.publicExponent = publicExponent;
            this.certainty = certainty;
        }

        /// <summary>Gets the public exponent.</summary>
        public BigInteger PublicExponent
        {
            get { return publicExponent; }
        }

        /// <summary>Gets the certainty.</summary>
        public int Certainty
        {
            get { return certainty; }
        }

        /// <inheritdoc/>
        public override bool Equals(
            object obj)
        {
            RsaKeyGenerationParameters other = obj as RsaKeyGenerationParameters;

            if (other == null)
            {
                return false;
            }

            return certainty == other.certainty
                && publicExponent.Equals(other.publicExponent);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return certainty.GetHashCode() ^ publicExponent.GetHashCode();
        }
    }
}
