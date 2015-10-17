using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Agreement.Jpake
{
    /**
     * A pre-computed prime order group for use during a J-PAKE exchange.
     * <p>
     * Typically a Schnorr group is used.  In general, J-PAKE can use any prime order group
     * that is suitable for public key cryptography, including elliptic curve cryptography.
     * <p>
     * See {@link JPAKEPrimeOrderGroups} for convenient standard groups.
     * <p>
     * NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/DSA2_All.pdf">publishes</a>
     * many groups that can be used for the desired level of security.
     */
    public class JPAKEPrimeOrderGroup
    {
        private readonly BigInteger p;
        private readonly BigInteger q;
        private readonly BigInteger g;

        /**
         * Constructs a new {@link JPAKEPrimeOrderGroup}.
         * <p>
         * In general, you should use one of the pre-approved groups from
         * {@link JPAKEPrimeOrderGroups}, rather than manually constructing one.
         * <p>
         * The following basic checks are performed:
         * <ul>
         * <li>p-1 must be evenly divisible by q</li>
         * <li>g must be in [2, p-1]</li>
         * <li>g^q mod p must equal 1</li>
         * <li>p must be prime (within reasonably certainty)</li>
         * <li>q must be prime (within reasonably certainty)</li>
         * </ul>
         * <p>
         * The prime checks are performed using {@link BigInteger#isProbablePrime(int)},
         * and are therefore subject to the same probability guarantees.
         * <p>
         * These checks prevent trivial mistakes.
         * However, due to the small uncertainties if p and q are not prime,
         * advanced attacks are not prevented.
         * Use it at your own risk.
         *
         * @throws NullReferenceException if any argument is null
         * @throws InvalidOperationException if any of the above validations fail
         */
        public JPAKEPrimeOrderGroup(BigInteger p, BigInteger q, BigInteger g)
            : this(p, q, g, false)
        {
            /*
             * Don't skip the checks on user-specified groups.
             */
        }

        /**
         * Internal package-private constructor used by the pre-approved
         * groups in {@link JPAKEPrimeOrderGroups}.
         * These pre-approved groups can avoid the expensive checks.
         */
        public JPAKEPrimeOrderGroup(BigInteger p, BigInteger q, BigInteger g, bool skipChecks)
        {
            JPAKEUtil.ValidateNotNull(p, "p");
            JPAKEUtil.ValidateNotNull(q, "q");
            JPAKEUtil.ValidateNotNull(g, "g");

            if (!skipChecks)
            {
                if (!p.Subtract(JPAKEUtil.ONE).Mod(q).Equals(JPAKEUtil.ZERO))
                {
                    throw new ArgumentException("p-1 must be evenly divisible by q");
                }
                if (g.CompareTo(BigInteger.ValueOf(2)) == -1 || g.CompareTo(p.Subtract(JPAKEUtil.ONE)) == 1)
                {
                    throw new ArgumentException("g must be in [2, p-1]");
                }
                if (!g.ModPow(q, p).Equals(JPAKEUtil.ONE))
                {
                    throw new ArgumentException("g^q mod p must equal 1");
                }
                /*
                 * Note these checks do not guarantee that p and q are prime.
                 * We just have reasonable certainty that they are prime.
                 */
                if (!p.IsProbablePrime(20))
                {
                    throw new ArgumentException("p must be prime");
                }
                if (!q.IsProbablePrime(20))
                {
                    throw new ArgumentException("q must be prime");
                }
            }

            this.p = p;
            this.q = q;
            this.g = g;
        }

        public BigInteger P
        {
            get { return p; }
        }

        public BigInteger Q
        {
            get { return q; }
        }

        public BigInteger G
        {
            get { return g; }
        }
    }
}
