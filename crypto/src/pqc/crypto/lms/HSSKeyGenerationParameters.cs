using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

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

            LmsParameters[] copy = Arrays.CopyBuffer(lmsParameters);

            // SP 800-208 sec. 4: one hash function throughout - within each level and across the hierarchy
            for (int i = 0; i < copy.Length; ++i)
            {
                LmsParameters level = copy[i];
                if (level == null)
                    throw new ArgumentException($"HSS level {i} has no parameters", nameof(lmsParameters));

                if (!level.UsesOneHashFunction())
                {
                    throw new ArgumentException(
                        $"HSS level {i} mixes hash functions between its LMS tree and LM-OTS keys (SP 800-208 sec. 4)",
                        nameof(lmsParameters));
                }

                if (!level.UsesSameLmsHashFunctionAs(copy[0]))
                {
                    throw new ArgumentException(
                        $"HSS level {i} uses a different hash function from level 0 (SP 800-208 sec. 4)",
                        nameof(lmsParameters));
                }
            }

            return copy;
        }

        private readonly LmsParameters[] m_lmsParameters;

        /// <summary>Base constructor - parameters and a source of randomness.</summary>
        /// <param name="lmsParameters">
        /// An array of <see cref="LmsParameters"/>, one per level in the hierarchy (from 1 to 8 levels).
        /// </param>
        /// <param name="random">The random byte source.</param>
        public HssKeyGenerationParameters(LmsParameters[] lmsParameters, SecureRandom random)
            : this(random, ValidateLmsParameters(lmsParameters))
        {
        }

        private HssKeyGenerationParameters(SecureRandom random, LmsParameters[] lmsParameters)
            : base(random, LmsUtilities.CalculateStrength(lmsParameters[0]))
        {
            m_lmsParameters = lmsParameters;
        }

        public int Depth => m_lmsParameters.Length;

        /// <sumamry>
        /// The parameters of one level of the hierarchy, 0 being the root.
        /// </sumamry>
        /// <remarks>
        /// <see cref="Depth"/> gives the range.
        /// </remarks>
        /// <exception cref="IndexOutOfRangeException">
        /// If <paramref name="index"/> is not in [0, <see cref="Depth"/>).
        /// </exception>
        public LmsParameters GetLmsParameters(int index) => m_lmsParameters[index];
    }
}
