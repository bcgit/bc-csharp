using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public class FalconKeyGenerationParameters
        : KeyGenerationParameters
    {
        private FalconParameters parameters;

        public FalconKeyGenerationParameters(SecureRandom random, FalconParameters parameters)
            : base(random, 320)
        {
            this.parameters = parameters;
        }

        public FalconParameters GetParameters()
        {
            return this.parameters;
        }
    }
}
