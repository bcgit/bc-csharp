using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>The parameters for generating LMS keys.</summary>
    public class LmsKeyGenerationParameters
        : KeyGenerationParameters
    {
        private static LmsParameters ValidateLmsParameters(LmsParameters lmsParameters)
        {
            if (lmsParameters == null)
                throw new ArgumentNullException(nameof(lmsParameters));

            if (!lmsParameters.UsesOneHashFunction())
            {
                throw new ArgumentException(
                    "LMS tree and LM-OTS parameter sets must use the same hash function (SP 800-208 sec. 4)",
                    nameof(lmsParameters));
            }

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

        /// <summary>Gets the lms parameters.</summary>
        public LmsParameters LmsParameters => m_lmsParameters;
    }
}
