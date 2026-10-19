using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    /// <summary>The parameters for generating NTRU LPRime keys.</summary>
    public class NtruLPRimeKeyGenerationParameters : KeyGenerationParameters
    {
        private NtruLPRimeParameters _primeParameters;

        /// <summary>Create a new <see cref="NtruLPRimeKeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="ntruPrimeParameters">The ntru prime parameters.</param>
        public NtruLPRimeKeyGenerationParameters(SecureRandom random, NtruLPRimeParameters ntruPrimeParameters) : base(random,256)
        {
            this._primeParameters = ntruPrimeParameters;
        }

        /// <summary>Gets the parameters.</summary>
        public NtruLPRimeParameters Parameters => _primeParameters;

    }
}
