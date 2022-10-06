using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public class LMSKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly LMSParameters m_lmsParameters;

        /**
         * Base constructor - parameters and a source of randomness.
         *
         * @param lmsParameters LMS parameter set to use.
         * @param random   the random byte source.
         */
        public LMSKeyGenerationParameters(LMSParameters lmsParameters, SecureRandom random)
            : base(random, LmsUtils.CalculateStrength(lmsParameters)) // TODO: need something for "strength"
        {
            m_lmsParameters = lmsParameters;
        }

        public LMSParameters LmsParameters => m_lmsParameters;
    }
}
