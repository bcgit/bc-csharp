using Org.BouncyCastle.Security;
using System;

namespace Org.BouncyCastle.Pqc.Math.LinearAlgebra
{
    public class GF2mField
    {

        /*
          * degree - degree of the field polynomial - the field polynomial ring -
          * polynomial ring over the finite field GF(2)
          */

        private int degree = 0;

        private int polynomial;

        /**
         * create a finite field GF(2^m)
         *
         * @param degree the degree of the field
         */
        public GF2mField(int degree)
        {
            if (degree >= 32)
            {
                throw new ArgumentException(
                    " Error: the degree of field is too large ");
            }
            if (degree < 1)
            {
                throw new ArgumentException(
                    " Error: the degree of field is non-positive ");
            }
            this.degree = degree;
            polynomial = PolynomialRingGF2.GetIrreduciblePolynomial(degree);
        }

        /**
         * create a finite field GF(2^m) with the fixed field polynomial
         *
         * @param degree the degree of the field
         * @param poly   the field polynomial
         */
        public GF2mField(int degree, int poly)
        {
            if (degree != PolynomialRingGF2.Degree(poly))
            {
                throw new ArgumentException(
                    " Error: the degree is not correct");
            }
            if (!PolynomialRingGF2.IsIrreducible(poly))
            {
                throw new ArgumentException(
                    " Error: given polynomial is reducible");
            }
            this.degree = degree;
            polynomial = poly;

        }

        public GF2mField(byte[] enc)
        {
            if (enc.Length != 4)
            {
                throw new ArgumentException(
                    "byte array is not an encoded finite field");
            }
            polynomial = LittleEndianConversions.OS2IP(enc);
            if (!PolynomialRingGF2.IsIrreducible(polynomial))
            {
                throw new ArgumentException(
                    "byte array is not an encoded finite field");
            }

            degree = PolynomialRingGF2.Degree(polynomial);
        }

        public GF2mField(GF2mField field)
        {
            degree = field.degree;
            polynomial = field.polynomial;
        }

        /**
         * return degree of the field
         *
         * @return degree of the field
         */
        public int GetDegree()
        {
            return degree;
        }

        /**
         * return the field polynomial
         *
         * @return the field polynomial
         */
        public int GetPolynomial()
        {
            return polynomial;
        }

        /**
         * return the encoded form of this field
         *
         * @return the field in byte array form
         */
        public byte[] GetEncoded()
        {
            return LittleEndianConversions.I2OSP(polynomial);
        }

        /**
         * Return sum of two elements
         *
         * @param a
         * @param b
         * @return a+b
         */
        public int add(int a, int b)
        {
            return a ^ b;
        }

        /**
         * Return product of two elements
         *
         * @param a
         * @param b
         * @return a*b
         */
        public int Mult(int a, int b)
        {
            return PolynomialRingGF2.modMultiply(a, b, polynomial);
        }

        /**
         * compute exponentiation a^k
         *
         * @param a a field element a
         * @param k k degree
         * @return a^k
         */
        public int Exp(int a, int k)
        {
            if (k == 0)
            {
                return 1;
            }
            if (a == 0)
            {
                return 0;
            }
            if (a == 1)
            {
                return 1;
            }
            int result = 1;
            if (k < 0)
            {
                a = Inverse(a);
                k = -k;
            }
            while (k != 0)
            {
                if ((k & 1) == 1)
                {
                    result = Mult(result, a);
                }
                a = Mult(a, a);
                //k >>>= 1;
                uint kTmp = (uint)k;
                kTmp >>= 1;
                k = (int) kTmp;
            }
            return result;
        }

        /**
         * compute the multiplicative inverse of a
         *
         * @param a a field element a
         * @return a<sup>-1</sup>
         */
        public int Inverse(int a)
        {
            int d = (1 << degree) - 2;

            return Exp(a, d);
        }

        /**
         * compute the square root of an integer
         *
         * @param a a field element a
         * @return a<sup>1/2</sup>
         */
        public int SqRoot(int a)
        {
            for (int i = 1; i < degree; i++)
            {
                a = Mult(a, a);
            }
            return a;
        }

        /**
         * create a random field element using PRNG sr
         *
         * @param sr SecureRandom
         * @return a random element
         */
        public int GetRandomElement(SecureRandom sr)
        {
            int result = RandUtils.NextInt(sr, 1 << degree);
            return result;
        }

        /**
         * create a random non-zero field element
         *
         * @return a random element
         */
        //public int getRandomNonZeroElement()
        //{
        //    return getRandomNonZeroElement(CryptoServicesRegistrar.getSecureRandom());
        //}

        /**
         * create a random non-zero field element using PRNG sr
         *
         * @param sr SecureRandom
         * @return a random non-zero element
         */
        public int GetRandomNonZeroElement(SecureRandom sr)
        {
            int controltime = 1 << 20;
            int count = 0;
            int result = RandUtils.NextInt(sr, 1 << degree);
            while ((result == 0) && (count < controltime))
            {
                result = RandUtils.NextInt(sr, 1 << degree);
                count++;
            }
            if (count == controltime)
            {
                result = 1;
            }
            return result;
        }

        /**
         * @return true if e is encoded element of this field and false otherwise
         */
        public bool IsElementOfThisField(int e)
        {
            // e is encoded element of this field iff 0<= e < |2^m|
            if (degree == 31)
            {
                return e >= 0;
            }
            return e >= 0 && e < (1 << degree);
        }

        /*
          * help method for visual control
          */
        public String ElementToStr(int a)
        {
            String s = "";
            for (int i = 0; i < degree; i++)
            {
                if (((byte)a & 0x01) == 0)
                {
                    s = "0" + s;
                }
                else
                {
                    s = "1" + s;
                }
                //a >>>= 1;
                uint aTmp = (uint)a;
                aTmp >>= 1;
                a = (int)aTmp;
            }
            return s;
        }

        /**
         * checks if given object is equal to this field.
         * <p>
         * The method returns false whenever the given object is not GF2m.
         *
         * @param other object
         * @return true or false
         */
        public bool Equals(Object other)
        {
            if ((other == null) || !(other is GF2mField))
        {
                return false;
            }

            GF2mField otherField = (GF2mField)other;

            if ((degree == otherField.degree)
                && (polynomial == otherField.polynomial))
            {
                return true;
            }

            return false;
        }

        public int HashCode()
        {
            return polynomial;
        }

        /**
         * Returns a human readable form of this field.
         *
         * @return a human readable form of this field.
         */
        public String ToString()
        {
            String str = "Finite Field GF(2^" + degree + ") = " + "GF(2)[X]/<"
                + PolyToString(polynomial) + "> ";
            return str;
        }

        private static String PolyToString(int p)
        {
            String str = "";
            if (p == 0)
            {
                str = "0";
            }
            else
            {
                byte b = (byte)(p & 0x01);
                if (b == 1)
                {
                    str = "1";
                }
                //p >>>= 1;
                uint pTmp = (uint)p;
                pTmp >>= 1;
                p = (int)pTmp;
                int i = 1;
                while (p != 0)
                {
                    b = (byte)(p & 0x01);
                    if (b == 1)
                    {
                        str = str + "+x^" + i;
                    }
                    //p >>>= 1;
                    pTmp = (uint) p;
                    pTmp >>= 1;
                    p = (int)pTmp;
                    i++;
                }
            }
            return str;
        }
    }
}