using System;

namespace Org.BouncyCastle.Pqc.Math.LinearAlgebra
{
    /**
 * This class describes operations with polynomials over finite field GF(2), i e
 * polynomial ring R = GF(2)[X]. All operations are defined only for polynomials
 * with degree &lt;=32. For the polynomial representation the map f: R-&gt;Z,
 * poly(X)-&gt;poly(2) is used, where integers have the binary representation. For
 * example: X^7+X^3+X+1 -&gt; (00...0010001011)=139 Also for polynomials type
 * Integer is used.
 *
 * @see GF2mField
 */
    public class PolynomialRingGF2
    {

        /**
         * Default constructor (private).
         */
        private PolynomialRingGF2()
        {
            // empty
        }

        /**
         * Return sum of two polyomials
         *
         * @param p polynomial
         * @param q polynomial
         * @return p+q
         */

        public static int Add(int p, int q)
        {
            return p ^ q;
        }

        /**
         * Return product of two polynomials
         *
         * @param p polynomial
         * @param q polynomial
         * @return p*q
         */

        public static long Multiply(int p, int q)
        {
            long result = 0;
            if (q != 0)
            {
                long q1 = q & 0x00000000ffffffffL;

                while (p != 0)
                {
                    byte b = (byte)(p & 0x01);
                    if (b == 1)
                    {
                        result ^= q1;
                    }
                    p = Utils.UnsignedRightBitShiftInt(p, 1);
                    q1 <<= 1;

                }
            }
            return result;
        }

        /**
         * Compute the product of two polynomials modulo a third polynomial.
         *
         * @param a the first polynomial
         * @param b the second polynomial
         * @param r the reduction polynomial
         * @return <tt>a * b mod r</tt>
         */
        public static int modMultiply(int a, int b, int r)
        {
            int result = 0;
            int p = Remainder(a, r);
            int q = Remainder(b, r);
            if (q != 0)
            {
                int d = 1 << Degree(r);

                while (p != 0)
                {
                    byte pMod2 = (byte)(p & 0x01);
                    if (pMod2 == 1)
                    {
                        result ^= q;
                    }
                    p = Utils.UnsignedRightBitShiftInt(p, 1);
                    q <<= 1;
                    if (q >= d)
                    {
                        q ^= r;
                    }
                }
            }
            return result;
        }

        /**
         * Return the degree of a polynomial
         *
         * @param p polynomial p
         * @return degree(p)
         */

        public static int Degree(int p)
        {
            int result = -1;
            while (p != 0)
            {
                result++;
                p = Utils.UnsignedRightBitShiftInt(p, 1);
            }
            return result;
        }

        /**
         * Return the degree of a polynomial
         *
         * @param p polynomial p
         * @return degree(p)
         */

        public static int Degree(long p)
        {
            int result = 0;
            while (p != 0)
            {
                result++;
                p = Utils.UnsignedRightBitShiftLong(p, 1);
            }
            return result - 1;
        }

        /**
         * Return the remainder of a polynomial division of two polynomials.
         *
         * @param p dividend
         * @param q divisor
         * @return <tt>p mod q</tt>
         */
        public static int Remainder(int p, int q)
        {
            int result = p;

            if (q == 0)
            {
                // -DM Console.Error.WriteLine
                Console.Error.WriteLine("Error: to be divided by 0");
                return 0;
            }

            while (Degree(result) >= Degree(q))
            {
                result ^= q << (Degree(result) - Degree(q));
            }

            return result;
        }

        /**
         * Return the rest of devision two polynomials
         *
         * @param p polinomial
         * @param q polinomial
         * @return p mod q
         */

        public static int Rest(long p, int q)
        {
            long p1 = p;
            if (q == 0)
            {
                // -DM Console.Error.WriteLine
                Console.Error.WriteLine("Error: to be divided by 0");
                return 0;
            }
            long q1 = q & 0x00000000ffffffffL;

            while ((Utils.UnsignedRightBitShiftLong(p1, 32)) != 0)
            {
                p1 ^= q1 << (Degree(p1) - Degree(q1));
            }

            int result = (int)(p1 & 0xffffffff);
            while (Degree(result) >= Degree(q))
            {
                result ^= q << (Degree(result) - Degree(q));
            }

            return result;
        }

        /**
         * Return the greatest common divisor of two polynomials
         *
         * @param p polinomial
         * @param q polinomial
         * @return GCD(p, q)
         */

        public static int Gcd(int p, int q)
        {
            int a, b, c;
            a = p;
            b = q;
            while (b != 0)
            {
                c = Remainder(a, b);
                a = b;
                b = c;

            }
            return a;
        }

        /**
         * Checking polynomial for irreducibility
         *
         * @param p polinomial
         * @return true if p is irreducible and false otherwise
         */

        public static bool IsIrreducible(int p)
        {
            if (p == 0)
            {
                return false;
            }
            uint tmpDeg = (uint)Degree(p);
            int d = (int) tmpDeg >> 1;
            int u = 2;
            for (int i = 0; i < d; i++)
            {
                u = modMultiply(u, u, p);
                if (Gcd(u ^ 2, p) != 1)
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * Creates irreducible polynomial with degree d
         *
         * @param deg polynomial degree
         * @return irreducible polynomial p
         */
        public static int GetIrreduciblePolynomial(int deg)
        {
            if (deg < 0)
            {
                // -DM Console.Error.WriteLine
                Console.Error.WriteLine("The Degree is negative");
                return 0;
            }
            if (deg > 31)
            {
                // -DM Console.Error.WriteLine
                Console.Error.WriteLine("The Degree is more then 31");
                return 0;
            }
            if (deg == 0)
            {
                return 1;
            }
            int a = 1 << deg;
            a++;
            int b = 1 << (deg + 1);
            for (int i = a; i < b; i += 2)
            {
                if (IsIrreducible(i))
                {
                    return i;
                }
            }
            return 0;
        }
    }
}
