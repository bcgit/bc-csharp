using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public sealed class BikeKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly BikeParameters m_parameters;

        /// <summary>Create a new <see cref="BikeKeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="parameters">The parameters.</param>
        public BikeKeyGenerationParameters(SecureRandom random, BikeParameters parameters)
            : base(random, 256)
        {
            m_parameters = parameters;
        }

        /// <summary>Gets the parameters.</summary>
        public BikeParameters Parameters => m_parameters;
    }
}
