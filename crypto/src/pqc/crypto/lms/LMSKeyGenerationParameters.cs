using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public class LmsKeyGenerationParameters
        : KeyGenerationParameters
    {
        private static LmsParameters ValidateLmsParameters(LmsParameters lmsParameters)
        {
            if (lmsParameters == null)
                throw new ArgumentNullException(nameof(lmsParameters));

            lmsParameters.CheckHashFunction();
            return lmsParameters;
        }

        private readonly LmsParameters m_lmsParameters;

        /**
         * Base constructor - parameters and a source of randomness.
         *
         * @param lmsParameters LMS parameter set to use.
         * @param random   the random byte source.
         */
        public LmsKeyGenerationParameters(LmsParameters lmsParameters, SecureRandom random)
            : base(random, LmsUtilities.CalculateStrength(ValidateLmsParameters(lmsParameters))) // TODO: need something for "strength"
        {
            m_lmsParameters = lmsParameters;
        }

        public LmsParameters LmsParameters => m_lmsParameters;
    }
}
