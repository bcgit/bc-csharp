using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    /// <summary>The parameters for generating FrodoKEM keys.</summary>
    public class FrodoKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly FrodoParameters m_parameters;

        /// <summary>Create a new <see cref="FrodoKeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="frodoParameters">The frodo parameters.</param>
        public FrodoKeyGenerationParameters(SecureRandom random, FrodoParameters frodoParameters)
            : base(random, 256)
        {
            m_parameters = frodoParameters;
        }

        /// <summary>Gets the parameters.</summary>
        public FrodoParameters Parameters => m_parameters;
    }
}
