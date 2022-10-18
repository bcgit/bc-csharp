using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    internal class BikePolynomial
    {
        /**
         * For the polynomial representation the map f: R->Z*,
         * <tt>poly(X) -> [coef_0, coef_1, ...]</tt> is used, where
         * <tt>coef_i</tt> is the <tt>i</tt>th coefficient of the polynomial
         * represented as int (see {@link GF2mField}). The polynomials are stored
         * as int arrays.
         */
        private readonly int[] m_coefficients;

        /**
         * Construct a monomial of the given degree over the finite field GF(2^m).
         *
         * @param field  the finite field GF(2^m)
         * @param degree the degree of the monomial
         */
        internal BikePolynomial(int degree)
        {
            // Initial value (X^r + 1)
            this.m_coefficients = new int[degree + 1];
            this.m_coefficients[degree] = 1;
            this.m_coefficients[0] ^= 1;
        }

        /**
         * Construct the polynomial over the given finite field GF(2^m) from the
         * given coefficient vector.
         *
         * @param field  finite field GF2m
         * @param coeffs the coefficient vector
         */
        private BikePolynomial(int[] coeffs)
        {
            this.m_coefficients = NormalForm(coeffs);
        }

        /**
         * Create a polynomial over the finite field GF(2^m).
         *
         * @param field the finite field GF(2^m)
         * @param enc   byte[] polynomial in byte array form
         */
        internal BikePolynomial(byte[] enc)
        {
            // decodes polynomial
            this.m_coefficients = new int[enc.Length];
            for (int i = 0; i < m_coefficients.Length; i++)
            {
                m_coefficients[i] = enc[i];
                if ((m_coefficients[i] >> 1) != 0)
                    throw new ArgumentException(
                        "Error: byte array is not encoded polynomial over given finite field GF2m");
            }
            // if HC = 0 for non-zero polynomial, returns error
            if ((m_coefficients.Length != 1) && (m_coefficients[m_coefficients.Length - 1] == 0))
                throw new ArgumentException("Error: byte array is not encoded polynomial over given finite field GF2m");
        }

        /**
         * Returns encoded polynomial, i.e., this polynomial in byte array form
         *
         * @return the encoded polynomial
         */
        internal byte[] GetEncoded()
        {
            byte[] res = new byte[m_coefficients.Length];
            for (int i = 0; i < m_coefficients.Length; i++)
            {
                res[i] = (byte)m_coefficients[i];
            }
            return res;
        }

        /**
         * Compute the sum of this polynomial and the given polynomial.
         *
         * @param addend the addend
         * @return <tt>this + a</tt> (newly created)
         */
        internal BikePolynomial Add(BikePolynomial addend)
        {
            int[] resultCoeff = Add(m_coefficients, addend.m_coefficients);
            return new BikePolynomial(resultCoeff);
        }

        /**
         * Compute the sum of two polynomials a and b over the finite field
         * <tt>GF(2^m)</tt>.
         *
         * @param a the first polynomial
         * @param b the second polynomial
         * @return a + b
         */
        private int[] Add(int[] a, int[] b)
        {
            int[] result, addend;
            if (a.Length < b.Length)
            {
                result = new int[b.Length];
                Array.Copy(b, 0, result, 0, b.Length);
                addend = a;
            }
            else
            {
                result = new int[a.Length];
                Array.Copy(a, 0, result, 0, a.Length);
                addend = b;
            }

            for (int i = addend.Length - 1; i >= 0; i--)
            {
                result[i] ^= addend[i];
            }

            return result;
        }

        /**
         * Compute the product of a polynomial a with an element from the finite
         * field <tt>GF(2^m)</tt>.
         *
         * @param a       the polynomial
         * @param element an element of the finite field GF(2^m)
         * @return <tt>a * element</tt>
         */
        private int[] MultWithElement(int[] a, int element)
        {
            return element == 0 ? new int[1] : Arrays.Clone(a);
        }

        /**
         * Compute the product of a polynomial with a monomial X^k.
         *
         * @param a the polynomial
         * @param k the degree of the monomial
         * @return <tt>a * X^k</tt>
         */
        private static int[] MultWithMonomial(int[] a, int k)
        {
            int d = ComputeDegree(a);
            if (d == -1)
                return new int[1];

            int[] result = new int[k + d + 1];
            Array.Copy(a, 0, result, k, d + 1);
            return result;
        }

        /**
         * Compute the result of the division of two polynomials over the field
         * <tt>GF(2^m)</tt>.
         *
         * @param a the first polynomial
         * @param f the second polynomial
         * @return int[][] {q,r}, where a = q*f+r and deg(r) &lt; deg(f);
         */
        private int[][] Div(int[] a, int[] f)
        {
            int df = ComputeDegree(f);
            if (df == -1)
                throw new ArithmeticException("Division by zero.");

            int degreeR1 = ComputeDegree(a);
            int[][] result = new int[2][];
            result[0] = new int[1]{ 0 };
            result[1] = Arrays.CopyOf(a, degreeR1 + 1);

            while (df <= degreeR1)
            {
                int[] q;
                int[] coeff = new int[1];
                coeff[0] = degreeR1 == -1 ? 0 : result[1][degreeR1];
                q = MultWithElement(f, coeff[0]);
                int n = degreeR1 - df;
                q = MultWithMonomial(q, n);
                coeff = MultWithMonomial(coeff, n);
                result[0] = Add(coeff, result[0]);
                result[1] = Add(q, result[1]);
                degreeR1 = ComputeDegree(result[1]);
            }
            return result;
        }

        /**
         * Compute the product of two polynomials over the field <tt>GF(2^m)</tt>
         * using a Karatzuba like multiplication.
         *
         * @param a the first polynomial
         * @param b the second polynomial
         * @return a * b
         */
        private int[] Multiply(int[] a, int[] b)
        {
            int[] mult1, mult2;
            if (ComputeDegree(a) < ComputeDegree(b))
            {
                mult1 = b;
                mult2 = a;
            }
            else
            {
                mult1 = a;
                mult2 = b;
            }

            mult1 = NormalForm(mult1);
            mult2 = NormalForm(mult2);

            if (mult2.Length == 1)
                return MultWithElement(mult1, mult2[0]);

            int d1 = mult1.Length;
            int d2 = mult2.Length;
            int[] result;

            if (d2 != d1)
            {
                int[] res1 = new int[d2];
                int[] res2 = new int[d1 - d2];
                Array.Copy(mult1, 0, res1, 0, res1.Length);
                Array.Copy(mult1, d2, res2, 0, res2.Length);
                res1 = Multiply(res1, mult2);
                res2 = Multiply(res2, mult2);
                res2 = MultWithMonomial(res2, d2);
                result = Add(res1, res2);
            }
            else
            {
                d2 = (int)((uint)(d1 + 1) >> 1);
                int d = d1 - d2;
                int[] firstPartMult1 = new int[d2];
                int[] firstPartMult2 = new int[d2];
                int[] secondPartMult1 = new int[d];
                int[] secondPartMult2 = new int[d];
                Array.Copy(mult1, 0, firstPartMult1, 0, firstPartMult1.Length);
                Array.Copy(mult1, d2, secondPartMult1, 0, secondPartMult1.Length);
                Array.Copy(mult2, 0, firstPartMult2, 0, firstPartMult2.Length);
                Array.Copy(mult2, d2, secondPartMult2, 0, secondPartMult2.Length);
                int[] helpPoly1 = Add(firstPartMult1, secondPartMult1);
                int[] helpPoly2 = Add(firstPartMult2, secondPartMult2);
                int[] res1 = Multiply(firstPartMult1, firstPartMult2);
                int[] res2 = Multiply(helpPoly1, helpPoly2);
                int[] res3 = Multiply(secondPartMult1, secondPartMult2);
                res2 = Add(res2, res1);
                res2 = Add(res2, res3);
                res3 = MultWithMonomial(res3, d2);
                result = Add(res2, res3);
                result = MultWithMonomial(result, d2);
                result = Add(result, res1);
            }

            return result;
        }

        /**
         * Reduce a polynomial modulo another polynomial.
         *
         * @param a the polynomial
         * @param f the reduction polynomial
         * @return <tt>a mod f</tt>
         */
        private int[] Mod(int[] a, int[] f)
        {
            int df = ComputeDegree(f);
            if (df == -1)
                throw new ArithmeticException("Division by zero");

            int degreeR = ComputeDegree(a);
            int[] result = Arrays.CopyOf(a, degreeR + 1);

            while (df <= degreeR)
            {
                int coeff = degreeR == -1 ? 0 : result[degreeR];
                int[] q = MultWithMonomial(f, degreeR - df);
                q = MultWithElement(q, coeff);
                result = Add(q, result);
                degreeR = ComputeDegree(result);
            }
            return result;
        }

        /**
         * Compute the degree of a polynomial.
         *
         * @param a the polynomial
         * @return the degree of the polynomial <tt>a</tt>. If <tt>a</tt> is
         *         the zero polynomial, return -1.
         */
        private static int ComputeDegree(int[] a)
        {
            int degree;
            for (degree = a.Length - 1; degree >= 0 && a[degree] == 0; degree--)
            {
            }
            return degree;
        }

        /**
         * Strip leading zero coefficients from the given polynomial.
         *
         * @param a the polynomial
         * @return the reduced polynomial
         */
        private static int[] NormalForm(int[] a)
        {
            int d = ComputeDegree(a);

            // if a is the zero polynomial
            if (d == -1)
            {
                // return new zero polynomial
                return new int[1];
            }

            // if a already is in normal form
            if (a.Length == d + 1)
            {
                // return a clone of a
                return Arrays.Clone(a);
            }

            // else, reduce a
            int[] result = new int[d + 1];
            Array.Copy(a, 0, result, 0, d + 1);
            return result;
        }

        /**
         * Compute the product of this polynomial and another polynomial modulo a
         * third polynomial.
         *
         * @param a another polynomial
         * @param b the reduction polynomial
         * @return <tt>this * a mod b</tt>
         */
        internal BikePolynomial ModKaratsubaMultiplyBigDeg(BikePolynomial a, BikePolynomial b)
        {
            int[] resultCoeff = ModKaratsubaMultiplyBigDeg(m_coefficients, a.m_coefficients, b.m_coefficients);
            return new BikePolynomial(resultCoeff);
        }

        /**
         * Compute the inverse of this polynomial modulo the given polynomial.
         *
         * @param a the reduction polynomial
         * @return <tt>this^(-1) mod a</tt>
         */
        internal BikePolynomial ModInverseBigDeg(BikePolynomial a)
        {
            int[] resultCoeff = ModInvBigDeg(m_coefficients, a.m_coefficients);
            return new BikePolynomial(resultCoeff);
        }

        private int[] ModInvBigDeg(int[] b, int[] g)
        {
            int[] r0 = NormalForm(g);
            int[] r1 = Mod(b, g);
            int[] s0 = { 0 };
            int[] s1 = { 1 };
            int[] s2;
            int[][] q;
            while (ComputeDegree(r1) != -1)
            {
                q = Div(r0, r1);
                r0 = NormalForm(r1);
                r1 = NormalForm(q[1]);
                s2 = Add(s0, ModKaratsubaMultiplyBigDeg(q[0], s1, g));
                s0 = NormalForm(s1);
                s1 = NormalForm(s2);
            }
            return s0;
        }

        /**
         * Compute the product of two polynomials modulo a third polynomial over the
         * finite field <tt>GF(2^m)</tt>.
         *
         * @param aa the first polynomial
         * @param bb the second polynomial
         * @param g the reduction polynomial
         * @return <tt>a * b mod g</tt>
         */
        private int[] ModKaratsubaMultiplyBigDeg(int[] aa, int[] bb, int[] g)
        {
            int[] a, b;
            if (aa.Length >= bb.Length)
            {
                a = aa;
                b = bb;
            }
            else
            {
                a = bb;
                b = aa;
            }

            int n = a.Length;
            int m = b.Length;

            int[] D = new int[(n + m) / 2];
            int[] S = new int[n + m - 1];
            int[] T = new int[n + m - 1];
            int[] C = new int[n + m - 1];

            for (int i = 0; i < m; i++)
            {
                D[i] = a[i] * b[i];
            }

            for (int i = 1; i < n + m - 2; i++)
            {
                int pLimit = System.Math.Min(m, (i + 1) >> 1);
                for (int p = 0; p < pLimit; p++)
                {
                    int q = i - p;

                    int ap = a[p];
                    int aq = q < a.Length ? a[q] : 0;

                    int bp = b[p];
                    int dp = D[p];

                    if (q < m)
                    {
                        int bq = b[q];
                        int dq = D[q];

                        S[i] = S[i] + (ap + aq) * (bp + bq);
                        T[i] = T[i] + dp + dq;
                    }
                    else if (q < n)
                    {
                        S[i] = S[i] + ((ap + aq) * bp);
                        T[i] = T[i] + dp;
                    }
                }
            }

            for (int i = 0; i < n + m - 1; i++)
            {
                if (i == 0)
                {
                    C[i] = D[i] % 2;
                }
                else if (i == n + m - 2)
                {
                    C[i] = (a[a.Length - 1] * b[b.Length - 1]) % 2;
                }
                else if (i % 2 == 1)
                {
                    C[i] = (S[i] - T[i]) % 2;
                }
                else
                {
                    C[i] = (S[i] - T[i] + D[i / 2]) % 2;
                }
            }

            return Mod(C, g);
        }
    }
}
