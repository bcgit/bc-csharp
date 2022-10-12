using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Pqc.Math.LinearAlgebra
{
    public class PolynomialGF2mSmallM
    {

        /**
         * the finite field GF(2^m)
         */
        private GF2mField field;

        /**
         * the degree of this polynomial
         */
        private int degree;

        /**
         * For the polynomial representation the map f: R->Z*,
         * <tt>poly(X) -> [coef_0, coef_1, ...]</tt> is used, where
         * <tt>coef_i</tt> is the <tt>i</tt>th coefficient of the polynomial
         * represented as int (see {@link GF2mField}). The polynomials are stored
         * as int arrays.
         */
        private int[] coefficients;

        /*
          * some types of polynomials
          */

        /**
         * Constant used for polynomial construction (see constructor
         * {@link #PolynomialGF2mSmallM(GF2mField, int, char, SecureRandom)}).
         */
        public const char RANDOM_IRREDUCIBLE_POLYNOMIAL = 'I';

        /**
         * Construct the zero polynomial over the finite field GF(2^m).
         *
         * @param field the finite field GF(2^m)
         */
        public PolynomialGF2mSmallM(GF2mField field)
        {
            this.field = field;
            degree = -1;
            coefficients = new int[1];
        }

        /**
         * Construct a polynomial over the finite field GF(2^m).
         *
         * @param field            the finite field GF(2^m)
         * @param deg              degree of polynomial
         * @param typeOfPolynomial type of polynomial
         * @param sr               PRNG
         */
        public PolynomialGF2mSmallM(GF2mField field, int deg,
                                    char typeOfPolynomial, SecureRandom sr)
        {
            this.field = field;

            switch (typeOfPolynomial)
            {
                case PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL:
                    coefficients = CreateRandomIrreduciblePolynomial(deg, sr);
                    break;
                default:
                    throw new ArgumentException(" Error: type "
                        + typeOfPolynomial
                        + " is not defined for GF2smallmPolynomial");
            }
            ComputeDegree();
        }

        /**
         * Create an irreducible polynomial with the given degree over the field
         * <tt>GF(2^m)</tt>.
         *
         * @param deg polynomial degree
         * @param sr  source of randomness
         * @return the generated irreducible polynomial
         */
        private int[] CreateRandomIrreduciblePolynomial(int deg, SecureRandom sr)
        {
            int[] resCoeff = new int[deg + 1];
            resCoeff[deg] = 1;
            resCoeff[0] = field.GetRandomNonZeroElement(sr);
            for (int i = 1; i < deg; i++)
            {
                resCoeff[i] = field.GetRandomElement(sr);
            }
            while (!IsIrreducible(resCoeff))
            {
                int n = RandUtils.NextInt(sr, deg);
                if (n == 0)
                {
                    resCoeff[0] = field.GetRandomNonZeroElement(sr);
                }
                else
                {
                    resCoeff[n] = field.GetRandomElement(sr);
                }
            }
            return resCoeff;
        }

        /**
         * Construct a monomial of the given degree over the finite field GF(2^m).
         *
         * @param field  the finite field GF(2^m)
         * @param degree the degree of the monomial
         */
        public PolynomialGF2mSmallM(GF2mField field, int degree)
        {
            this.field = field;
            this.degree = degree;
            coefficients = new int[degree + 1];
            coefficients[degree] = 1;
        }

        /**
         * Construct the polynomial over the given finite field GF(2^m) from the
         * given coefficient vector.
         *
         * @param field  finite field GF2m
         * @param coeffs the coefficient vector
         */
        public PolynomialGF2mSmallM(GF2mField field, int[] coeffs)
        {
            this.field = field;
            coefficients = NormalForm(coeffs);
            ComputeDegree();
        }

        /**
         * Create a polynomial over the finite field GF(2^m).
         *
         * @param field the finite field GF(2^m)
         * @param enc   byte[] polynomial in byte array form
         */
        public PolynomialGF2mSmallM(GF2mField field, byte[] enc)
        {
            this.field = field;

            // decodes polynomial
            int d = 8;
            int count = 1;
            while (field.GetDegree() > d)
            {
                count++;
                d += 8;
            }

            if ((enc.Length % count) != 0)
            {
                throw new ArgumentException(
                    " Error: byte array is not encoded polynomial over given finite field GF2m");
            }

            coefficients = new int[enc.Length / count];
            count = 0;
            for (int i = 0; i < coefficients.Length; i++)
            {
                for (int j = 0; j < d; j += 8)
                {
                    coefficients[i] ^= (enc[count++] & 0x000000ff) << j;
                }
                if (!this.field.IsElementOfThisField(coefficients[i]))
                {
                    throw new ArgumentException(
                        " Error: byte array is not encoded polynomial over given finite field GF2m");
                }
            }
            // if HC = 0 for non-zero polynomial, returns error
            if ((coefficients.Length != 1)
                && (coefficients[coefficients.Length - 1] == 0))
            {
                throw new ArgumentException(
                    " Error: byte array is not encoded polynomial over given finite field GF2m");
            }
            ComputeDegree();
        }

        /**
         * Copy constructor.
         *
         * @param other another {@link PolynomialGF2mSmallM}
         */
        public PolynomialGF2mSmallM(PolynomialGF2mSmallM other)
        {
            // field needs not to be cloned since it is immutable
            field = other.field;
            degree = other.degree;
            coefficients = IntUtils.Clone(other.coefficients);
        }

        /**
         * Create a polynomial over the finite field GF(2^m) out of the given
         * coefficient vector. The finite field is also obtained from the
         * {@link GF2mVector}.
         *
         * @param vect the coefficient vector
         */
        public PolynomialGF2mSmallM(GF2mVector vect)
        {
            new PolynomialGF2mSmallM(vect.GetField(), vect.GetIntArrayForm());
        }

        /*
          * ------------------------
          */

        /**
         * Return the degree of this polynomial
         *
         * @return int degree of this polynomial if this is zero polynomial return
         *         -1
         */
        public int GetDegree()
        {
            int d = coefficients.Length - 1;
            if (coefficients[d] == 0)
            {
                return -1;
            }
            return d;
        }

        /**
         * @return the head coefficient of this polynomial
         */
        public int GetHeadCoefficient()
        {
            if (degree == -1)
            {
                return 0;
            }
            return coefficients[degree];
        }

        /**
         * Return the head coefficient of a polynomial.
         *
         * @param a the polynomial
         * @return the head coefficient of <tt>a</tt>
         */
        private static int HeadCoefficient(int[] a)
        {
            int degree = ComputeDegree(a);
            if (degree == -1)
            {
                return 0;
            }
            return a[degree];
        }

        /**
         * Return the coefficient with the given index.
         *
         * @param index the index
         * @return the coefficient with the given index
         */
        public int GetCoefficient(int index)
        {
            if ((index < 0) || (index > degree))
            {
                return 0;
            }
            return coefficients[index];
        }

        /**
         * Returns encoded polynomial, i.e., this polynomial in byte array form
         *
         * @return the encoded polynomial
         */
        public byte[] GetEncoded()
        {
            int d = 8;
            int count = 1;
            while (field.GetDegree() > d)
            {
                count++;
                d += 8;
            }

            byte[] res = new byte[coefficients.Length * count];
            count = 0;
            for (int i = 0; i < coefficients.Length; i++)
            {
                for (int j = 0; j < d; j += 8)
                {
                    res[count++] = (byte)(Utils.UnsignedRightBitShiftInt(coefficients[i], j));
                }
            }

            return res;
        }

        /**
         * Evaluate this polynomial <tt>p</tt> at a value <tt>e</tt> (in
         * <tt>GF(2^m)</tt>) with the Horner scheme.
         *
         * @param e the element of the finite field GF(2^m)
         * @return <tt>this(e)</tt>
         */
        public int evaluateAt(int e)
        {
            int result = coefficients[degree];
            for (int i = degree - 1; i >= 0; i--)
            {
                result = field.Mult(result, e) ^ coefficients[i];
            }
            return result;
        }

        /**
         * Compute the sum of this polynomial and the given polynomial.
         *
         * @param addend the addend
         * @return <tt>this + a</tt> (newly created)
         */
        public PolynomialGF2mSmallM add(PolynomialGF2mSmallM addend)
        {
            int[] resultCoeff = Add(coefficients, addend.coefficients);
            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        /**
         * Add the given polynomial to this polynomial (overwrite this).
         *
         * @param addend the addend
         */
        public void AddToThis(PolynomialGF2mSmallM addend)
        {
            coefficients = Add(coefficients, addend.coefficients);
            ComputeDegree();
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
                result[i] = field.add(result[i], addend[i]);
            }

            return result;
        }

        /**
         * Compute the sum of this polynomial and the monomial of the given degree.
         *
         * @param degree the degree of the monomial
         * @return <tt>this + X^k</tt>
         */
        public PolynomialGF2mSmallM AddMonomial(int degree)
        {
            int[] monomial = new int[degree + 1];
            monomial[degree] = 1;
            int[] resultCoeff = Add(coefficients, monomial);
            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        /**
         * Compute the product of this polynomial with an element from GF(2^m).
         *
         * @param element an element of the finite field GF(2^m)
         * @return <tt>this * element</tt> (newly created)
         * @throws ArithmeticException if <tt>element</tt> is not an element of the finite
         * field this polynomial is defined over.
         */
        public PolynomialGF2mSmallM MultWithElement(int element)
        {
            if (!field.IsElementOfThisField(element))
            {
                throw new ArithmeticException(
                    "Not an element of the finite field this polynomial is defined over.");
            }
            int[] resultCoeff = MultWithElement(coefficients, element);
            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        /**
         * Multiply this polynomial with an element from GF(2^m).
         *
         * @param element an element of the finite field GF(2^m)
         * @throws ArithmeticException if <tt>element</tt> is not an element of the finite
         * field this polynomial is defined over.
         */
        public void MultThisWithElement(int element)
        {
            if (!field.IsElementOfThisField(element))
            {
                throw new ArithmeticException(
                    "Not an element of the finite field this polynomial is defined over.");
            }
            coefficients = MultWithElement(coefficients, element);
            ComputeDegree();
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
            int degree = ComputeDegree(a);
            if (degree == -1 || element == 0)
            {
                return new int[1];
            }

            if (element == 1)
            {
                return IntUtils.Clone(a);
            }

            int[] result = new int[degree + 1];
            for (int i = degree; i >= 0; i--)
            {
                result[i] = field.Mult(a[i], element);
            }

            return result;
        }

        /**
         * Compute the product of this polynomial with a monomial X^k.
         *
         * @param k the degree of the monomial
         * @return <tt>this * X^k</tt>
         */
        public PolynomialGF2mSmallM MultWithMonomial(int k)
        {
            int[] resultCoeff = MultWithMonomial(coefficients, k);
            return new PolynomialGF2mSmallM(field, resultCoeff);
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
            {
                return new int[1];
            }
            int[] result = new int[d + k + 1];
            Array.Copy(a, 0, result, k, d + 1);
            return result;
        }

        /**
         * Divide this polynomial by the given polynomial.
         *
         * @param f a polynomial
         * @return polynomial pair = {q,r} where this = q*f+r and deg(r) &lt;
         *         deg(f);
         */
        public PolynomialGF2mSmallM[] Div(PolynomialGF2mSmallM f)
        {
            int[][] resultCoeffs = Div(coefficients, f.coefficients);
            return new PolynomialGF2mSmallM[]{
            new PolynomialGF2mSmallM(field, resultCoeffs[0]),
            new PolynomialGF2mSmallM(field, resultCoeffs[1])};
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
            int da = ComputeDegree(a) + 1;
            if (df == -1)
            {
                throw new ArithmeticException("Division by zero.");
            }
            int[][] result = new int[2][];
            result[0] = new int[1];
            result[1] = new int[da];
            int hc = HeadCoefficient(f);
            hc = field.Inverse(hc);
            result[0][0] = 0;
            Array.Copy(a, 0, result[1], 0, result[1].Length);
            while (df <= ComputeDegree(result[1]))
            {
                int[] q;
                int[] coeff = new int[1];
                coeff[0] = field.Mult(HeadCoefficient(result[1]), hc);
                q = MultWithElement(f, coeff[0]);
                int n = ComputeDegree(result[1]) - df;
                q = MultWithMonomial(q, n);
                coeff = MultWithMonomial(coeff, n);
                result[0] = Add(coeff, result[0]);
                result[1] = Add(q, result[1]);
            }
            return result;
        }

        /**
         * Return the greatest common divisor of this and a polynomial <i>f</i>
         *
         * @param f polynomial
         * @return GCD(this, f)
         */
        public PolynomialGF2mSmallM Gcd(PolynomialGF2mSmallM f)
        {
            int[] resultCoeff = Gcd(coefficients, f.coefficients);
            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        /**
         * Return the greatest common divisor of two polynomials over the field
         * <tt>GF(2^m)</tt>.
         *
         * @param f the first polynomial
         * @param g the second polynomial
         * @return <tt>gcd(f, g)</tt>
         */
        private int[] Gcd(int[] f, int[] g)
        {
            int[] a = f;
            int[] b = g;
            if (ComputeDegree(a) == -1)
            {
                return b;
            }
            while (ComputeDegree(b) != -1)
            {
                int[] c = Mod(a, b);
                a = new int[b.Length];
                Array.Copy(b, 0, a, 0, a.Length);
                b = new int[c.Length];
                Array.Copy(c, 0, b, 0, b.Length);
            }
            int coeff = field.Inverse(HeadCoefficient(a));
            return MultWithElement(a, coeff);
        }

        /**
         * Compute the product of this polynomial and the given factor using a
         * Karatzuba like scheme.
         *
         * @param factor the polynomial
         * @return <tt>this * factor</tt>
         */
        public PolynomialGF2mSmallM Multiply(PolynomialGF2mSmallM factor)
        {
            int[] resultCoeff = Multiply(coefficients, factor.coefficients);
            return new PolynomialGF2mSmallM(field, resultCoeff);
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
            {
                return MultWithElement(mult1, mult2[0]);
            }

            int d1 = mult1.Length;
            int d2 = mult2.Length;
            int[] result = new int[d1 + d2 - 1];

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
                d2 = Utils.UnsignedRightBitShiftInt(d1 + 1, 1);
                int d = d1 - d2;
                int[] firstPartMult1 = new int[d2];
                int[] firstPartMult2 = new int[d2];
                int[] secondPartMult1 = new int[d];
                int[] secondPartMult2 = new int[d];
                Array.Copy(mult1, 0, firstPartMult1, 0,
                        firstPartMult1.Length);
                Array.Copy(mult1, d2, secondPartMult1, 0,
                    secondPartMult1.Length);
                Array.Copy(mult2, 0, firstPartMult2, 0,
                        firstPartMult2.Length);
                Array.Copy(mult2, d2, secondPartMult2, 0,
                    secondPartMult2.Length);
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

        /*
          * ---------------- PART II ----------------
          *
          */

        /**
         * Check a polynomial for irreducibility over the field <tt>GF(2^m)</tt>.
         *
         * @param a the polynomial to check
         * @return true if a is irreducible, false otherwise
         */
        private bool IsIrreducible(int[] a)
        {
            if (a[0] == 0)
            {
                return false;
            }
            int d = ComputeDegree(a) >> 1;
            int[] u = { 0, 1 };
            int[] Y = { 0, 1 };
            int fieldDegree = field.GetDegree();
            for (int i = 0; i < d; i++)
            {
                for (int j = fieldDegree - 1; j >= 0; j--)
                {
                    u = ModMultiply(u, u, a);
                }
                u = NormalForm(u);
                int[] g = Gcd(Add(u, Y), a);
                if (ComputeDegree(g) != 0)
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * Reduce this polynomial modulo another polynomial.
         *
         * @param f the reduction polynomial
         * @return <tt>this mod f</tt>
         */
        public PolynomialGF2mSmallM Mod(PolynomialGF2mSmallM f)
        {
            int[] resultCoeff = Mod(coefficients, f.coefficients);
            return new PolynomialGF2mSmallM(field, resultCoeff);
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
            {
                throw new ArithmeticException("Division by zero");
            }
            int[] result = new int[a.Length];
            int hc = HeadCoefficient(f);
            hc = field.Inverse(hc);
            Array.Copy(a, 0, result, 0, result.Length);
            while (df <= ComputeDegree(result))
            {
                int[] q;
                int coeff = field.Mult(HeadCoefficient(result), hc);
                q = MultWithMonomial(f, ComputeDegree(result) - df);
                q = MultWithElement(q, coeff);
                result = Add(q, result);
            }
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
        public PolynomialGF2mSmallM ModMultiply(PolynomialGF2mSmallM a,
                                                PolynomialGF2mSmallM b)
        {
            int[] resultCoeff = ModMultiply(coefficients, a.coefficients,
                b.coefficients);
            return new PolynomialGF2mSmallM(field, resultCoeff);
        }



        /**
         * Square this polynomial using a squaring matrix.
         *
         * @param matrix the squaring matrix
         * @return <tt>this^2</tt> modulo the reduction polynomial implicitly
         *         given via the squaring matrix
         */
        public PolynomialGF2mSmallM ModSquareMatrix(PolynomialGF2mSmallM[] matrix)
        {

            int length = matrix.Length;

            int[] resultCoeff = new int[length];
            int[] thisSquare = new int[length];

            // square each entry of this polynomial
            for (int i = 0; i < coefficients.Length; i++)
            {
                thisSquare[i] = field.Mult(coefficients[i], coefficients[i]);
            }

            // do matrix-vector multiplication
            for (int i = 0; i < length; i++)
            {
                // compute scalar product of i-th row and coefficient vector
                for (int j = 0; j < length; j++)
                {
                    if (i >= matrix[j].coefficients.Length)
                    {
                        continue;
                    }
                    int scalarTerm = field.Mult(matrix[j].coefficients[i],
                        thisSquare[j]);
                    resultCoeff[i] = field.add(resultCoeff[i], scalarTerm);
                }
            }

            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        /**
         * Compute the product of two polynomials modulo a third polynomial over the
         * finite field <tt>GF(2^m)</tt>.
         *
         * @param a the first polynomial
         * @param b the second polynomial
         * @param g the reduction polynomial
         * @return <tt>a * b mod g</tt>
         */
        private int[] ModMultiply(int[] a, int[] b, int[] g)
        {
            return Mod(Multiply(a, b), g);
        }

        /**
         * Compute the square root of this polynomial modulo the given polynomial.
         *
         * @param a the reduction polynomial
         * @return <tt>this^(1/2) mod a</tt>
         */
        public PolynomialGF2mSmallM ModSquareRoot(PolynomialGF2mSmallM a)
        {
            int[] resultCoeff = IntUtils.Clone(coefficients);
            int[] help = ModMultiply(resultCoeff, resultCoeff, a.coefficients);
            while (!IsEqual(help, coefficients))
            {
                resultCoeff = NormalForm(help);
                help = ModMultiply(resultCoeff, resultCoeff, a.coefficients);
            }

            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        /**
         * Compute the square root of this polynomial using a square root matrix.
         *
         * @param matrix the matrix for computing square roots in
         *               <tt>(GF(2^m))^t</tt> the polynomial ring defining the
         *               square root matrix
         * @return <tt>this^(1/2)</tt> modulo the reduction polynomial implicitly
         *         given via the square root matrix
         */
        public PolynomialGF2mSmallM ModSquareRootMatrix(
            PolynomialGF2mSmallM[] matrix)
        {

            int length = matrix.Length;

            int[] resultCoeff = new int[length];

            // do matrix multiplication
            for (int i = 0; i < length; i++)
            {
                // compute scalar product of i-th row and j-th column
                for (int j = 0; j < length; j++)
                {
                    if (i >= matrix[j].coefficients.Length)
                    {
                        continue;
                    }
                    if (j < coefficients.Length)
                    {
                        int scalarTerm = field.Mult(matrix[j].coefficients[i],
                            coefficients[j]);
                        resultCoeff[i] = field.add(resultCoeff[i], scalarTerm);
                    }
                }
            }

            // compute the square root of each entry of the result coefficients
            for (int i = 0; i < length; i++)
            {
                resultCoeff[i] = field.SqRoot(resultCoeff[i]);
            }

            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        /**
         * Compute the result of the division of this polynomial by another
         * polynomial modulo a third polynomial.
         *
         * @param divisor the divisor
         * @param modulus the reduction polynomial
         * @return <tt>this * divisor^(-1) mod modulus</tt>
         */
        public PolynomialGF2mSmallM ModDiv(PolynomialGF2mSmallM divisor,
                                           PolynomialGF2mSmallM modulus)
        {
            int[] resultCoeff = ModDiv(coefficients, divisor.coefficients,
                modulus.coefficients);
            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        /**
         * Compute the result of the division of two polynomials modulo a third
         * polynomial over the field <tt>GF(2^m)</tt>.
         *
         * @param a the first polynomial
         * @param b the second polynomial
         * @param g the reduction polynomial
         * @return <tt>a * b^(-1) mod g</tt>
         */
        private int[] ModDiv(int[] a, int[] b, int[] g)
        {
            int[] r0 = NormalForm(g);
            int[] r1 = Mod(b, g);
            int[] s0 = { 0 };
            int[] s1 = Mod(a, g);
            int[] s2;
            int[][] q;
            while (ComputeDegree(r1) != -1)
            {
                q = Div(r0, r1);
                r0 = NormalForm(r1);
                r1 = NormalForm(q[1]);
                s2 = Add(s0, ModMultiply(q[0], s1, g));
                s0 = NormalForm(s1);
                s1 = NormalForm(s2);

            }
            int hc = HeadCoefficient(r0);
            s0 = MultWithElement(s0, field.Inverse(hc));
            return s0;
        }

        /**
         * Compute the inverse of this polynomial modulo the given polynomial.
         *
         * @param a the reduction polynomial
         * @return <tt>this^(-1) mod a</tt>
         */
        public PolynomialGF2mSmallM ModInverse(PolynomialGF2mSmallM a)
        {
            int[] unit = { 1 };
            int[] resultCoeff = ModDiv(unit, coefficients, a.coefficients);
            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        /**
         * Compute a polynomial pair (a,b) from this polynomial and the given
         * polynomial g with the property b*this = a mod g and deg(a)&lt;=deg(g)/2.
         *
         * @param g the reduction polynomial
         * @return PolynomialGF2mSmallM[] {a,b} with b*this = a mod g and deg(a)&lt;=
         *         deg(g)/2
         */
        public PolynomialGF2mSmallM[] ModPolynomialToFracton(PolynomialGF2mSmallM g)
        {
            int dg = g.degree >> 1;
            int[] a0 = NormalForm(g.coefficients);
            int[] a1 = Mod(coefficients, g.coefficients);
            int[] b0 = { 0 };
            int[] b1 = { 1 };
            while (ComputeDegree(a1) > dg)
            {
                int[][] q = Div(a0, a1);
                a0 = a1;
                a1 = q[1];
                int[] b2 = Add(b0, ModMultiply(q[0], b1, g.coefficients));
                b0 = b1;
                b1 = b2;
            }

            return new PolynomialGF2mSmallM[]{
            new PolynomialGF2mSmallM(field, a1),
            new PolynomialGF2mSmallM(field, b1)};
        }

        /**
         * checks if given object is equal to this polynomial.
         * <p>
         * The method returns false whenever the given object is not polynomial over
         * GF(2^m).
         *
         * @param other object
         * @return true or false
         */
        public bool equals(Object other)
        {

            if (other == null || !(other is PolynomialGF2mSmallM))
            {
                return false;
            }

            PolynomialGF2mSmallM p = (PolynomialGF2mSmallM)other;

            if ((field.Equals(p.field)) && (degree == p.degree)
                && (IsEqual(coefficients, p.coefficients)))
            {
                return true;
            }

            return false;
        }

        /**
         * Compare two polynomials given as int arrays.
         *
         * @param a the first polynomial
         * @param b the second polynomial
         * @return <tt>true</tt> if <tt>a</tt> and <tt>b</tt> represent the
         *         same polynomials, <tt>false</tt> otherwise
         */
        private static bool IsEqual(int[] a, int[] b)
        {
            int da = ComputeDegree(a);
            int db = ComputeDegree(b);
            if (da != db)
            {
                return false;
            }
            for (int i = 0; i <= da; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * @return the hash code of this polynomial
         */
        public int HashCode()
        {
            int hash = field.HashCode();
            for (int j = 0; j < coefficients.Length; j++)
            {
                hash = hash * 31 + coefficients[j];
            }
            return hash;
        }

        /**
         * Returns a human readable form of the polynomial.
         *
         * @return a human readable form of the polynomial.
         */
        public String toString()
        {
            String str = " Polynomial over " + field.ToString() + ": \n";

            for (int i = 0; i < coefficients.Length; i++)
            {
                str = str + field.ElementToStr(coefficients[i]) + "Y^" + i + "+";
            }
            str = str + ";";

            return str;
        }

        /**
         * Compute the degree of this polynomial. If this is the zero polynomial,
         * the degree is -1.
         */
        private void ComputeDegree()
        {
            for (degree = coefficients.Length - 1; degree >= 0
                && coefficients[degree] == 0; degree--)
            {
                ;
            }
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
                ;
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
                return IntUtils.Clone(a);
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
        public PolynomialGF2mSmallM ModKaratsubaMultiplyBigDeg(PolynomialGF2mSmallM a,
                                                               PolynomialGF2mSmallM b)
        {
            int[] resultCoeff = ModKaratsubaMultiplyBigDeg(coefficients, a.coefficients,
                    b.coefficients);
            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        /**
         * Compute the inverse of this polynomial modulo the given polynomial.
         *
         * @param a the reduction polynomial
         * @return <tt>this^(-1) mod a</tt>
         */
        public PolynomialGF2mSmallM ModInverseBigDeg(PolynomialGF2mSmallM a)
        {
            int[] unit = { 1 };
            int[] resultCoeff = ModDivBigDeg(unit, coefficients, a.coefficients);
            return new PolynomialGF2mSmallM(field, resultCoeff);
        }

        private int[] ModDivBigDeg(int[] a, int[] b, int[] g)
        {
            int[] r0 = NormalForm(g);
            int[] r1 = Mod(b, g);
            int[] s0 = { 0 };
            int[] s1 = Mod(a, g);
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
            int hc = HeadCoefficient(r0);
            s0 = MultWithElement(s0, field.Inverse(hc));
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
                a = Arrays.Clone(aa);
                b = Arrays.Clone(bb);
            }
            else
            {
                a = Arrays.Clone(bb);
                b = Arrays.Clone(aa);
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
                for (int p = 0; p < System.Math.Min(m, i); p++)
                {
                    int q = i - p;
                    if (p >= q)
                    {
                        break;
                    }

                    int ap = a[p];
                    int aq = 0;

                    if (q < a.Length)
                    {
                        aq = a[q];
                    }

                    int bp = b[p];
                    int dp = D[p];

                    if (q < m && p < m)
                    {
                        int bq = b[q];
                        int dq = D[q];

                        S[i] = S[i] + (ap + aq) * (bp + bq);
                        T[i] = T[i] + dp + dq;
                    }
                    else if (q >= m && q < n)
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
            int[] res = Mod(C, g);
            return res;
        }
    }
}
