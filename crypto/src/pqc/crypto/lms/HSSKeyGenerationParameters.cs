using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class HssKeyGenerationParameters
        : KeyGenerationParameters
    {
        private static LmsParameters[] ValidateLmsParameters(LmsParameters[] lmsParameters)
        {
            if (lmsParameters == null)
                throw new ArgumentNullException(nameof(lmsParameters));
            if (lmsParameters.Length < 1 || lmsParameters.Length > 8)  // RFC 8554, Section 6.
                throw new ArgumentException("length should be between 1 and 8 inclusive", nameof(lmsParameters));

            // SP 800-208 sec. 4: one hash function throughout - within each level and across the hierarchy
            for (int i = 0; i < lmsParameters.Length; ++i)
            {
                LmsParameters level = lmsParameters[i];
                if (level == null)
                    throw new ArgumentException($"HSS level {i} has no parameters", nameof(lmsParameters));

                if (!level.UsesOneHashFunction())
                {
                    throw new ArgumentException(
                        $"HSS level {i} mixes hash functions between its LMS tree and LM-OTS keys (SP 800-208 sec. 4)",
                        nameof(lmsParameters));
                }

                if (!level.UsesSameLmsHashFunctionAs(lmsParameters[0]))
                {
                    throw new ArgumentException(
                        $"HSS level {i} uses a different hash function from level 0 (SP 800-208 sec. 4)",
                        nameof(lmsParameters));
                }
            }

            return lmsParameters;
        }

        private readonly LmsParameters[] m_lmsParameters;

        /**
         * Base constructor - parameters and a source of randomness.
         *
         * @param lmsParameters array of LMS parameters, one per level in the hierarchy (up to 8 levels).
         * @param random   the random byte source.
         */
        public HssKeyGenerationParameters(LmsParameters[] lmsParameters, SecureRandom random)
            :base(random, LmsUtilities.CalculateStrength(ValidateLmsParameters(lmsParameters)[0]))
        {
            m_lmsParameters = lmsParameters;
        }

        public int Depth => m_lmsParameters.Length;

        public LmsParameters GetLmsParameters(int index)
        {
            if (index < 0 || index >= m_lmsParameters.Length)
                throw new ArgumentOutOfRangeException(nameof(index));

            return m_lmsParameters[index];
        }
    }
}
