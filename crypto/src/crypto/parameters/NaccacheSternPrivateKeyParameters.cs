using System;
using System.Collections.Generic;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /**
     * Private key parameters for NaccacheStern cipher. For details on this cipher,
     * please see
     *
     * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
     */
    public class NaccacheSternPrivateKeyParameters : NaccacheSternKeyParameters
    {
        private readonly BigInteger phiN;
        private readonly IList<BigInteger> smallPrimes;

        /**
         * Constructs a NaccacheSternPrivateKey
         *
         * @param g
         *            the public enryption parameter g
         * @param n
         *            the public modulus n = p*q
         * @param lowerSigmaBound
         *            the public lower sigma bound up to which data can be encrypted
         * @param smallPrimes
         *            the small primes, of which sigma is constructed in the right
         *            order. Each must divide exactly one of p - 1 and q - 1, so 2 is
         *            never valid: otherwise g^(phi(n) / p_i) = 1 for every g and
         *            decryption cannot recover the plaintext modulo p_i (this is not
         *            checked)
         * @param phi_n
         *            the private modulus phi(n) = (p-1)(q-1)
         */
        public NaccacheSternPrivateKeyParameters(
            BigInteger g,
            BigInteger n,
            int lowerSigmaBound,
            IList<BigInteger> smallPrimes,
            BigInteger phiN)
            : base(true, g, n, lowerSigmaBound)
        {
            this.smallPrimes = smallPrimes;
            this.phiN = phiN;
        }

        /// <summary>Gets the phi n.</summary>
        public BigInteger PhiN
        {
            get { return phiN; }
        }

        /// <summary>Gets the small primes list.</summary>
        public IList<BigInteger> SmallPrimesList
        {
            get { return smallPrimes; }
        }
    }
}
