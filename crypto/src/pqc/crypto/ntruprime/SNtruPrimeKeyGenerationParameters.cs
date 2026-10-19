using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public class SNtruPrimeKeyGenerationParameters : KeyGenerationParameters
    {
        private SNtruPrimeParameters _primeParameters;

        /// <summary>Create a new <see cref="SNtruPrimeKeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="ntruPrimeParameters">The ntru prime parameters.</param>
        public SNtruPrimeKeyGenerationParameters(SecureRandom random, SNtruPrimeParameters ntruPrimeParameters) : base(random,256)
        {
            this._primeParameters = ntruPrimeParameters;
        }

        /// <summary>Gets the parameters.</summary>
        public SNtruPrimeParameters Parameters => _primeParameters;

    }
}
