using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public sealed class SaberKeyGenerationParameters
        : KeyGenerationParameters
    {
        private SaberParameters parameters;

        /// <summary>Create a new <see cref="SaberKeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="saberParameters">The saber parameters.</param>
        public SaberKeyGenerationParameters(SecureRandom random, SaberParameters saberParameters)
            : base(random, 256)
        {
            this.parameters = saberParameters;
        }

        /// <summary>Gets the parameters.</summary>
        public SaberParameters Parameters => parameters;
    }
}
