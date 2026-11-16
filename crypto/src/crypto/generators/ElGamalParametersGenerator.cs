using System.Diagnostics;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    /// <summary>Generator for ElGamal domain parameters.</summary>
    public class ElGamalParametersGenerator
    {
        private int m_size;
        private int m_certainty;
        private SecureRandom m_random;

        /// <summary>Initialise the generator.</summary>
        /// <param name="size">The size of the prime to generate, in bits.</param>
        /// <param name="certainty">
        /// A measure of the uncertainty that the caller is willing to tolerate that the number is prime.
        /// </param>
        /// <param name="random">The source of randomness.</param>
        public void Init(int size, int certainty, SecureRandom random)
        {
            m_size = size;
            m_certainty = certainty;
            m_random = random;
        }

        /// <summary>Generates random ElGamal parameters of the given size, with given certainty.</summary>
        public ElGamalParameters GenerateParameters()
        {
            //
            // find a safe prime p where p = 2*q + 1, where p and q are prime.
            //
            //BigInteger[] safePrimes = DHParametersHelper.GenerateSafePrimes(m_size, m_certainty, m_random);

            //BigInteger p = safePrimes[0];
            //BigInteger q = safePrimes[1];
            //BigInteger g = DHParametersHelper.SelectGenerator(p, q, m_random);
            // Generate a safe prime p (p == 2.q + 1) for which 2 has order q
            BigInteger[] safePrimes = DHParametersHelper.GenerateSafePrimes(m_size, m_certainty, m_random,
                forGenerator2: true);
            BigInteger p = safePrimes[0];
            //BigInteger q = safePrimes[1];

            Debug.Assert((p.IntValue & 7) == 7);
            BigInteger g = BigInteger.Two;

            return new ElGamalParameters(p, g);
        }
    }
}
