using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public sealed class BikeKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly BikeParameters m_parameters;

        public BikeKeyGenerationParameters(SecureRandom random, BikeParameters parameters)
            : base(random, 256)
        {
            m_parameters = parameters;
        }

        public BikeParameters Parameters => m_parameters;
    }
}
