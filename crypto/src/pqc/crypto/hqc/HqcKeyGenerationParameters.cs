using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public class HqcKeyGenerationParameters : KeyGenerationParameters
    {
        private HqcParameters param;

        public HqcKeyGenerationParameters(
            SecureRandom random,
            HqcParameters param) : base(random, 256)
            {
                this.param = param;
            }

            public HqcParameters Parameters => param;
        }
}
