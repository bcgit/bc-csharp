using System;
using System.Diagnostics;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC
{
    public abstract class ECFieldElement
    {
        public abstract BigInteger ToBigInteger();
        public abstract string FieldName { get; }
        public abstract int FieldSize { get; }
        public abstract ECFieldElement Add(ECFieldElement b);
        public abstract ECFieldElement Subtract(ECFieldElement b);
        public abstract ECFieldElement Multiply(ECFieldElement b);
        public abstract ECFieldElement Divide(ECFieldElement b);
        public abstract ECFieldElement Negate();
        public abstract ECFieldElement Square();
        public abstract ECFieldElement Invert();
        public abstract ECFieldElement Sqrt();

        public virtual int BitLength
        {
            get { return ToBigInteger().BitLength; }
        }

        public virtual bool IsOne
        {
            get { return BitLength == 1; }
        }

        public virtual bool IsZero
        {
            get { return 0 == ToBigInteger().SignValue; }
        }

        public virtual bool TestBitZero()
        {
            return ToBigInteger().TestBit(0);
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as ECFieldElement);
        }

        public virtual bool Equals(ECFieldElement other)
        {
            if (this == other)
                return true;
            if (null == other)
                return false;
            return ToBigInteger().Equals(other.ToBigInteger());
        }

        public override int GetHashCode()
        {
            return ToBigInteger().GetHashCode();
        }

        public override string ToString()
        {
            return this.ToBigInteger().ToString(16);
        }

        public virtual byte[] GetEncoded()
        {
            return BigIntegers.AsUnsignedByteArray((FieldSize + 7) / 8, ToBigInteger());
        }
    }

    public class FpFieldElement
        : ECFieldElement
    {
        private readonly BigInteger q, r, x;

        internal static BigInteger CalculateResidue(BigInteger p)
        {
            int bitLength = p.BitLength;
            if (bitLength > 128)
            {
                BigInteger firstWord = p.ShiftRight(bitLength - 64);
                if (firstWord.LongValue == -1L)
                {
                    return BigInteger.One.ShiftLeft(bitLength).Subtract(p);
                }
            }
            return null;
        }

        [Obsolete("Use ECCurve.FromBigInteger to construct field elements")]
        public FpFieldElement(BigInteger q, BigInteger x)
            : this(q, CalculateResidue(q), x)
        {
        }

        internal FpFieldElement(BigInteger q, BigInteger r, BigInteger x)
        {
            if (x == null || x.SignValue < 0 || x.CompareTo(q) >= 0)
                throw new ArgumentException("value invalid in Fp field element", "x");

            this.q = q;
            this.r = r;
            this.x = x;
        }

        public override BigInteger ToBigInteger()
        {
            return x;
        }

        /**
         * return the field name for this field.
         *
         * @return the string "Fp".
         */
        public override string FieldName
        {
            get { return "Fp"; }
        }

        public override int FieldSize
        {
            get { return q.BitLength; }
        }

        public BigInteger Q
        {
            get { return q; }
        }

        public override ECFieldElement Add(
            ECFieldElement b)
        {
            return new FpFieldElement(q, r, ModAdd(x, b.ToBigInteger()));
        }

        public override ECFieldElement Subtract(
            ECFieldElement b)
        {
            BigInteger x2 = b.ToBigInteger();
            BigInteger x3 = x.Subtract(x2);
            if (x3.SignValue < 0)
            {
                x3 = x3.Add(q);
            }
            return new FpFieldElement(q, r, x3);
        }

        public override ECFieldElement Multiply(
            ECFieldElement b)
        {
            return new FpFieldElement(q, r, ModMult(x, b.ToBigInteger()));
        }

        public override ECFieldElement Divide(
            ECFieldElement b)
        {
            return new FpFieldElement(q, r, ModMult(x, b.ToBigInteger().ModInverse(q)));
        }

        public override ECFieldElement Negate()
        {
            return x.SignValue == 0 ? this : new FpFieldElement(q, r, q.Subtract(x));
        }

        public override ECFieldElement Square()
        {
            return new FpFieldElement(q, r, ModMult(x, x));
        }

        public override ECFieldElement Invert()
        {
            // TODO Modular inversion can be faster for a (Generalized) Mersenne Prime.
            return new FpFieldElement(q, r, x.ModInverse(q));
        }

        // D.1.4 91
        /**
         * return a sqrt root - the routine verifies that the calculation
         * returns the right value - if none exists it returns null.
         */
        public override ECFieldElement Sqrt()
        {
            if (!q.TestBit(0))
                throw Platform.CreateNotImplementedException("even value of q");

            // p mod 4 == 3
            if (q.TestBit(1))
            {
                // TODO Can this be optimised (inline the Square?)
                // z = g^(u+1) + p, p = 4u + 3
                ECFieldElement z = new FpFieldElement(q, r, x.ModPow(q.ShiftRight(2).Add(BigInteger.One), q));

                return z.Square().Equals(this) ? z : null;
            }

            // p mod 4 == 1
            BigInteger qMinusOne = q.Subtract(BigInteger.One);

            BigInteger legendreExponent = qMinusOne.ShiftRight(1);
            if (!(x.ModPow(legendreExponent, q).Equals(BigInteger.One)))
                return null;

            BigInteger u = qMinusOne.ShiftRight(2);
            BigInteger k = u.ShiftLeft(1).Add(BigInteger.One);

            BigInteger X = this.x;
            BigInteger fourX = ModDouble(ModDouble(X)); ;

            BigInteger U, V;
            Random rand = new Random();
            do
            {
                BigInteger P;
                do
                {
                    P = new BigInteger(q.BitLength, rand);
                }
                while (P.CompareTo(q) >= 0
                    || !(ModMult(P, P).Subtract(fourX).ModPow(legendreExponent, q).Equals(qMinusOne)));

                BigInteger[] result = LucasSequence(P, X, k);
                U = result[0];
                V = result[1];

                if (ModMult(V, V).Equals(fourX))
                {
                    // Integer division by 2, mod q
                    if (V.TestBit(0))
                    {
                        V = V.Add(q);
                    }

                    V = V.ShiftRight(1);

                    Debug.Assert(ModMult(V, V).Equals(X));

                    return new FpFieldElement(q, r, V);
                }
            }
            while (U.Equals(BigInteger.One) || U.Equals(qMinusOne));

            return null;
        }

        private BigInteger[] LucasSequence(
            BigInteger	P,
            BigInteger	Q,
            BigInteger	k)
        {
            // TODO Research and apply "common-multiplicand multiplication here"

            int n = k.BitLength;
            int s = k.GetLowestSetBit();

            Debug.Assert(k.TestBit(s));

            BigInteger Uh = BigInteger.One;
            BigInteger Vl = BigInteger.Two;
            BigInteger Vh = P;
            BigInteger Ql = BigInteger.One;
            BigInteger Qh = BigInteger.One;

            for (int j = n - 1; j >= s + 1; --j)
            {
                Ql = ModMult(Ql, Qh);

                if (k.TestBit(j))
                {
                    Qh = ModMult(Ql, Q);
                    Uh = ModMult(Uh, Vh);
                    Vl = ModReduce(Vh.Multiply(Vl).Subtract(P.Multiply(Ql)));
                    Vh = ModReduce(Vh.Multiply(Vh).Subtract(Qh.ShiftLeft(1)));
                }
                else
                {
                    Qh = Ql;
                    Uh = ModReduce(Uh.Multiply(Vl).Subtract(Ql));
                    Vh = ModReduce(Vh.Multiply(Vl).Subtract(P.Multiply(Ql)));
                    Vl = ModReduce(Vl.Multiply(Vl).Subtract(Ql.ShiftLeft(1)));
                }
            }

            Ql = ModMult(Ql, Qh);
            Qh = ModMult(Ql, Q);
            Uh = ModReduce(Uh.Multiply(Vl).Subtract(Ql));
            Vl = ModReduce(Vh.Multiply(Vl).Subtract(P.Multiply(Ql)));
            Ql = ModMult(Ql, Qh);

            for (int j = 1; j <= s; ++j)
            {
                Uh = ModMult(Uh, Vl);
                Vl = ModReduce(Vl.Multiply(Vl).Subtract(Ql.ShiftLeft(1)));
                Ql = ModMult(Ql, Ql);
            }

            return new BigInteger[] { Uh, Vl };
        }

        protected virtual BigInteger ModAdd(BigInteger x1, BigInteger x2)
        {
            BigInteger x3 = x1.Add(x2);
            if (x3.CompareTo(q) >= 0)
            {
                x3 = x3.Subtract(q);
            }
            return x3;
        }

        protected virtual BigInteger ModDouble(BigInteger x)
        {
            BigInteger _2x = x.ShiftLeft(1);
            if (_2x.CompareTo(q) >= 0)
            {
                _2x = _2x.Subtract(q);
            }
            return _2x;
        }

        protected virtual BigInteger ModMult(BigInteger x1, BigInteger x2)
        {
            return ModReduce(x1.Multiply(x2));
        }

        protected virtual BigInteger ModReduce(BigInteger x)
        {
            if (r != null)
            {
                bool negative = x.SignValue < 0;
                if (negative)
                {
                    x = x.Abs();
                }
                int qLen = q.BitLength;
                while (x.BitLength > (qLen + 1))
                {
                    BigInteger u = x.ShiftRight(qLen);
                    BigInteger v = x.Subtract(u.ShiftLeft(qLen));
                    if (!r.Equals(BigInteger.One))
                    {
                        u = u.Multiply(r);
                    }
                    x = u.Add(v);
                }
                while (x.CompareTo(q) >= 0)
                {
                    x = x.Subtract(q);
                }
                if (negative && x.SignValue != 0)
                {
                    x = q.Subtract(x);
                }
            }
            else
            {
                x = x.Mod(q);
            }
            return x;
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            FpFieldElement other = obj as FpFieldElement;

            if (other == null)
                return false;

            return Equals(other);
        }

        public virtual bool Equals(
            FpFieldElement other)
        {
            return q.Equals(other.q) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return q.GetHashCode() ^ base.GetHashCode();
        }
    }

//	/**
//	 * Class representing the Elements of the finite field
//	 * <code>F<sub>2<sup>m</sup></sub></code> in polynomial basis (PB)
//	 * representation. Both trinomial (Tpb) and pentanomial (Ppb) polynomial
//	 * basis representations are supported. Gaussian normal basis (GNB)
//	 * representation is not supported.
//	 */
//	public class F2mFieldElement
//		: ECFieldElement
//	{
//		/**
//		 * Indicates gaussian normal basis representation (GNB). Number chosen
//		 * according to X9.62. GNB is not implemented at present.
//		 */
//		public const int Gnb = 1;
//
//		/**
//		 * Indicates trinomial basis representation (Tpb). Number chosen
//		 * according to X9.62.
//		 */
//		public const int Tpb = 2;
//
//		/**
//		 * Indicates pentanomial basis representation (Ppb). Number chosen
//		 * according to X9.62.
//		 */
//		public const int Ppb = 3;
//
//		/**
//		 * Tpb or Ppb.
//		 */
//		private int representation;
//
//		/**
//		 * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
//		 */
//		private int m;
//
//		/**
//		 * Tpb: The integer <code>k</code> where <code>x<sup>m</sup> +
//		 * x<sup>k</sup> + 1</code> represents the reduction polynomial
//		 * <code>f(z)</code>.<br/>
//		 * Ppb: The integer <code>k1</code> where <code>x<sup>m</sup> +
//		 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//		 * represents the reduction polynomial <code>f(z)</code>.<br/>
//		 */
//		private int k1;
//
//		/**
//		 * Tpb: Always set to <code>0</code><br/>
//		 * Ppb: The integer <code>k2</code> where <code>x<sup>m</sup> +
//		 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//		 * represents the reduction polynomial <code>f(z)</code>.<br/>
//		 */
//		private int k2;
//
//		/**
//			* Tpb: Always set to <code>0</code><br/>
//			* Ppb: The integer <code>k3</code> where <code>x<sup>m</sup> +
//			* x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//			* represents the reduction polynomial <code>f(z)</code>.<br/>
//			*/
//		private int k3;
//
//		/**
//			* Constructor for Ppb.
//			* @param m  The exponent <code>m</code> of
//			* <code>F<sub>2<sup>m</sup></sub></code>.
//			* @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
//			* x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//			* represents the reduction polynomial <code>f(z)</code>.
//			* @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
//			* x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//			* represents the reduction polynomial <code>f(z)</code>.
//			* @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
//			* x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//			* represents the reduction polynomial <code>f(z)</code>.
//			* @param x The BigInteger representing the value of the field element.
//			*/
//		public F2mFieldElement(
//			int			m,
//			int			k1,
//			int			k2,
//			int			k3,
//			BigInteger	x)
//			: base(x)
//		{
//			if ((k2 == 0) && (k3 == 0))
//			{
//				this.representation = Tpb;
//			}
//			else
//			{
//				if (k2 >= k3)
//					throw new ArgumentException("k2 must be smaller than k3");
//				if (k2 <= 0)
//					throw new ArgumentException("k2 must be larger than 0");
//
//				this.representation = Ppb;
//			}
//
//			if (x.SignValue < 0)
//				throw new ArgumentException("x value cannot be negative");
//
//			this.m = m;
//			this.k1 = k1;
//			this.k2 = k2;
//			this.k3 = k3;
//		}
//
//		/**
//			* Constructor for Tpb.
//			* @param m  The exponent <code>m</code> of
//			* <code>F<sub>2<sup>m</sup></sub></code>.
//			* @param k The integer <code>k</code> where <code>x<sup>m</sup> +
//			* x<sup>k</sup> + 1</code> represents the reduction
//			* polynomial <code>f(z)</code>.
//			* @param x The BigInteger representing the value of the field element.
//			*/
//		public F2mFieldElement(
//			int			m,
//			int			k,
//			BigInteger	x)
//			: this(m, k, 0, 0, x)
//		{
//			// Set k1 to k, and set k2 and k3 to 0
//		}
//
//		public override string FieldName
//		{
//			get { return "F2m"; }
//		}
//
//		/**
//		* Checks, if the ECFieldElements <code>a</code> and <code>b</code>
//		* are elements of the same field <code>F<sub>2<sup>m</sup></sub></code>
//		* (having the same representation).
//		* @param a field element.
//		* @param b field element to be compared.
//		* @throws ArgumentException if <code>a</code> and <code>b</code>
//		* are not elements of the same field
//		* <code>F<sub>2<sup>m</sup></sub></code> (having the same
//		* representation).
//		*/
//		public static void CheckFieldElements(
//			ECFieldElement	a,
//			ECFieldElement	b)
//		{
//			if (!(a is F2mFieldElement) || !(b is F2mFieldElement))
//			{
//				throw new ArgumentException("Field elements are not "
//					+ "both instances of F2mFieldElement");
//			}
//
//			if ((a.x.SignValue < 0) || (b.x.SignValue < 0))
//			{
//				throw new ArgumentException(
//					"x value may not be negative");
//			}
//
//			F2mFieldElement aF2m = (F2mFieldElement)a;
//			F2mFieldElement bF2m = (F2mFieldElement)b;
//
//			if ((aF2m.m != bF2m.m) || (aF2m.k1 != bF2m.k1)
//				|| (aF2m.k2 != bF2m.k2) || (aF2m.k3 != bF2m.k3))
//			{
//				throw new ArgumentException("Field elements are not "
//					+ "elements of the same field F2m");
//			}
//
//			if (aF2m.representation != bF2m.representation)
//			{
//				// Should never occur
//				throw new ArgumentException(
//					"One of the field "
//					+ "elements are not elements has incorrect representation");
//			}
//		}
//
//		/**
//			* Computes <code>z * a(z) mod f(z)</code>, where <code>f(z)</code> is
//			* the reduction polynomial of <code>this</code>.
//			* @param a The polynomial <code>a(z)</code> to be multiplied by
//			* <code>z mod f(z)</code>.
//			* @return <code>z * a(z) mod f(z)</code>
//			*/
//		private BigInteger multZModF(
//			BigInteger a)
//		{
//			// Left-shift of a(z)
//			BigInteger az = a.ShiftLeft(1);
//			if (az.TestBit(this.m))
//			{
//				// If the coefficient of z^m in a(z) Equals 1, reduction
//				// modulo f(z) is performed: Add f(z) to to a(z):
//				// Step 1: Unset mth coeffient of a(z)
//				az = az.ClearBit(this.m);
//
//				// Step 2: Add r(z) to a(z), where r(z) is defined as
//				// f(z) = z^m + r(z), and k1, k2, k3 are the positions of
//				// the non-zero coefficients in r(z)
//				az = az.FlipBit(0);
//				az = az.FlipBit(this.k1);
//				if (this.representation == Ppb)
//				{
//					az = az.FlipBit(this.k2);
//					az = az.FlipBit(this.k3);
//				}
//			}
//			return az;
//		}
//
//		public override ECFieldElement Add(
//			ECFieldElement b)
//		{
//			// No check performed here for performance reasons. Instead the
//			// elements involved are checked in ECPoint.F2m
//			// checkFieldElements(this, b);
//			if (b.x.SignValue == 0)
//				return this;
//
//			return new F2mFieldElement(this.m, this.k1, this.k2, this.k3, this.x.Xor(b.x));
//		}
//
//		public override ECFieldElement Subtract(
//			ECFieldElement b)
//		{
//			// Addition and subtraction are the same in F2m
//			return Add(b);
//		}
//
//		public override ECFieldElement Multiply(
//			ECFieldElement b)
//		{
//			// Left-to-right shift-and-add field multiplication in F2m
//			// Input: Binary polynomials a(z) and b(z) of degree at most m-1
//			// Output: c(z) = a(z) * b(z) mod f(z)
//
//			// No check performed here for performance reasons. Instead the
//			// elements involved are checked in ECPoint.F2m
//			// checkFieldElements(this, b);
//			BigInteger az = this.x;
//			BigInteger bz = b.x;
//			BigInteger cz;
//
//			// Compute c(z) = a(z) * b(z) mod f(z)
//			if (az.TestBit(0))
//			{
//				cz = bz;
//			}
//			else
//			{
//				cz = BigInteger.Zero;
//			}
//
//			for (int i = 1; i < this.m; i++)
//			{
//				// b(z) := z * b(z) mod f(z)
//				bz = multZModF(bz);
//
//				if (az.TestBit(i))
//				{
//					// If the coefficient of x^i in a(z) Equals 1, b(z) is added
//					// to c(z)
//					cz = cz.Xor(bz);
//				}
//			}
//			return new F2mFieldElement(m, this.k1, this.k2, this.k3, cz);
//		}
//
//
//		public override ECFieldElement Divide(
//			ECFieldElement b)
//		{
//			// There may be more efficient implementations
//			ECFieldElement bInv = b.Invert();
//			return Multiply(bInv);
//		}
//
//		public override ECFieldElement Negate()
//		{
//			// -x == x holds for all x in F2m
//			return this;
//		}
//
//		public override ECFieldElement Square()
//		{
//			// Naive implementation, can probably be speeded up using modular
//			// reduction
//			return Multiply(this);
//		}
//
//		public override ECFieldElement Invert()
//		{
//			// Inversion in F2m using the extended Euclidean algorithm
//			// Input: A nonzero polynomial a(z) of degree at most m-1
//			// Output: a(z)^(-1) mod f(z)
//
//			// u(z) := a(z)
//			BigInteger uz = this.x;
//			if (uz.SignValue <= 0)
//			{
//				throw new ArithmeticException("x is zero or negative, " +
//					"inversion is impossible");
//			}
//
//			// v(z) := f(z)
//			BigInteger vz = BigInteger.One.ShiftLeft(m);
//			vz = vz.SetBit(0);
//			vz = vz.SetBit(this.k1);
//			if (this.representation == Ppb)
//			{
//				vz = vz.SetBit(this.k2);
//				vz = vz.SetBit(this.k3);
//			}
//
//			// g1(z) := 1, g2(z) := 0
//			BigInteger g1z = BigInteger.One;
//			BigInteger g2z = BigInteger.Zero;
//
//			// while u != 1
//			while (uz.SignValue != 0)
//			{
//				// j := deg(u(z)) - deg(v(z))
//				int j = uz.BitLength - vz.BitLength;
//
//				// If j < 0 then: u(z) <-> v(z), g1(z) <-> g2(z), j := -j
//				if (j < 0)
//				{
//					BigInteger uzCopy = uz;
//					uz = vz;
//					vz = uzCopy;
//
//					BigInteger g1zCopy = g1z;
//					g1z = g2z;
//					g2z = g1zCopy;
//
//					j = -j;
//				}
//
//				// u(z) := u(z) + z^j * v(z)
//				// Note, that no reduction modulo f(z) is required, because
//				// deg(u(z) + z^j * v(z)) <= max(deg(u(z)), j + deg(v(z)))
//				// = max(deg(u(z)), deg(u(z)) - deg(v(z)) + deg(v(z))
//				// = deg(u(z))
//				uz = uz.Xor(vz.ShiftLeft(j));
//
//				// g1(z) := g1(z) + z^j * g2(z)
//				g1z = g1z.Xor(g2z.ShiftLeft(j));
//				//                if (g1z.BitLength() > this.m) {
//				//                    throw new ArithmeticException(
//				//                            "deg(g1z) >= m, g1z = " + g1z.ToString(2));
//				//                }
//			}
//			return new F2mFieldElement(this.m, this.k1, this.k2, this.k3, g2z);
//		}
//
//		public override ECFieldElement Sqrt()
//		{
//			throw new ArithmeticException("Not implemented");
//		}
//
//		/**
//			* @return the representation of the field
//			* <code>F<sub>2<sup>m</sup></sub></code>, either of
//			* {@link F2mFieldElement.Tpb} (trinomial
//			* basis representation) or
//			* {@link F2mFieldElement.Ppb} (pentanomial
//			* basis representation).
//			*/
//		public int Representation
//		{
//			get { return this.representation; }
//		}
//
//		/**
//			* @return the degree <code>m</code> of the reduction polynomial
//			* <code>f(z)</code>.
//			*/
//		public int M
//		{
//			get { return this.m; }
//		}
//
//		/**
//			* @return Tpb: The integer <code>k</code> where <code>x<sup>m</sup> +
//			* x<sup>k</sup> + 1</code> represents the reduction polynomial
//			* <code>f(z)</code>.<br/>
//			* Ppb: The integer <code>k1</code> where <code>x<sup>m</sup> +
//			* x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//			* represents the reduction polynomial <code>f(z)</code>.<br/>
//			*/
//		public int K1
//		{
//			get { return this.k1; }
//		}
//
//		/**
//			* @return Tpb: Always returns <code>0</code><br/>
//			* Ppb: The integer <code>k2</code> where <code>x<sup>m</sup> +
//			* x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//			* represents the reduction polynomial <code>f(z)</code>.<br/>
//			*/
//		public int K2
//		{
//			get { return this.k2; }
//		}
//
//		/**
//			* @return Tpb: Always set to <code>0</code><br/>
//			* Ppb: The integer <code>k3</code> where <code>x<sup>m</sup> +
//			* x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//			* represents the reduction polynomial <code>f(z)</code>.<br/>
//			*/
//		public int K3
//		{
//			get { return this.k3; }
//		}
//
//		public override bool Equals(
//			object obj)
//		{
//			if (obj == this)
//				return true;
//
//			F2mFieldElement other = obj as F2mFieldElement;
//
//			if (other == null)
//				return false;
//
//			return Equals(other);
//		}
//
//		protected bool Equals(
//			F2mFieldElement other)
//		{
//			return m == other.m
//				&& k1 == other.k1
//				&& k2 == other.k2
//				&& k3 == other.k3
//				&& representation == other.representation
//				&& base.Equals(other);
//		}
//
//		public override int GetHashCode()
//		{
//			return base.GetHashCode() ^ m ^ k1 ^ k2 ^ k3;
//		}
//	}

    /**
     * Class representing the Elements of the finite field
     * <code>F<sub>2<sup>m</sup></sub></code> in polynomial basis (PB)
     * representation. Both trinomial (Tpb) and pentanomial (Ppb) polynomial
     * basis representations are supported. Gaussian normal basis (GNB)
     * representation is not supported.
     */
    public class F2mFieldElement
        : ECFieldElement
    {
        /**
         * Indicates gaussian normal basis representation (GNB). Number chosen
         * according to X9.62. GNB is not implemented at present.
         */
        public const int Gnb = 1;

        /**
         * Indicates trinomial basis representation (Tpb). Number chosen
         * according to X9.62.
         */
        public const int Tpb = 2;

        /**
         * Indicates pentanomial basis representation (Ppb). Number chosen
         * according to X9.62.
         */
        public const int Ppb = 3;

        /**
         * Tpb or Ppb.
         */
        private int representation;

        /**
         * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
         */
        private int m;

        /**
         * Tpb: The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction polynomial
         * <code>f(z)</code>.<br/>
         * Ppb: The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br/>
         */
        private int k1;

        /**
         * Tpb: Always set to <code>0</code><br/>
         * Ppb: The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br/>
         */
        private int k2;

        /**
            * Tpb: Always set to <code>0</code><br/>
            * Ppb: The integer <code>k3</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.<br/>
            */
        private int k3;

        /**
         * The <code>IntArray</code> holding the bits.
         */
        private IntArray x;

        /**
         * The number of <code>int</code>s required to hold <code>m</code> bits.
         */
        private readonly int t;

        /**
            * Constructor for Ppb.
            * @param m  The exponent <code>m</code> of
            * <code>F<sub>2<sup>m</sup></sub></code>.
            * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.
            * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.
            * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.
            * @param x The BigInteger representing the value of the field element.
            */
        public F2mFieldElement(
            int			m,
            int			k1,
            int			k2,
            int			k3,
            BigInteger	x)
        {
            // t = m / 32 rounded up to the next integer
            this.t = (m + 31) >> 5;
            this.x = new IntArray(x, t);

            if ((k2 == 0) && (k3 == 0))
            {
                this.representation = Tpb;
            }
            else
            {
                if (k2 >= k3)
                    throw new ArgumentException("k2 must be smaller than k3");
                if (k2 <= 0)
                    throw new ArgumentException("k2 must be larger than 0");

                this.representation = Ppb;
            }

            if (x.SignValue < 0)
                throw new ArgumentException("x value cannot be negative");

            this.m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
        }

        /**
            * Constructor for Tpb.
            * @param m  The exponent <code>m</code> of
            * <code>F<sub>2<sup>m</sup></sub></code>.
            * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
            * x<sup>k</sup> + 1</code> represents the reduction
            * polynomial <code>f(z)</code>.
            * @param x The BigInteger representing the value of the field element.
            */
        public F2mFieldElement(
            int			m,
            int			k,
            BigInteger	x)
            : this(m, k, 0, 0, x)
        {
            // Set k1 to k, and set k2 and k3 to 0
        }

        private F2mFieldElement(int m, int k1, int k2, int k3, IntArray x)
        {
            t = (m + 31) >> 5;
            this.x = x;
            this.m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;

            if ((k2 == 0) && (k3 == 0))
            {
                this.representation = Tpb;
            }
            else
            {
                this.representation = Ppb;
            }
        }

        public override BigInteger ToBigInteger()
        {
            return x.ToBigInteger();
        }

        public override string FieldName
        {
            get { return "F2m"; }
        }

        public override int FieldSize
        {
            get { return m; }
        }

        /**
        * Checks, if the ECFieldElements <code>a</code> and <code>b</code>
        * are elements of the same field <code>F<sub>2<sup>m</sup></sub></code>
        * (having the same representation).
        * @param a field element.
        * @param b field element to be compared.
        * @throws ArgumentException if <code>a</code> and <code>b</code>
        * are not elements of the same field
        * <code>F<sub>2<sup>m</sup></sub></code> (having the same
        * representation).
        */
        public static void CheckFieldElements(
            ECFieldElement	a,
            ECFieldElement	b)
        {
            if (!(a is F2mFieldElement) || !(b is F2mFieldElement))
            {
                throw new ArgumentException("Field elements are not "
                    + "both instances of F2mFieldElement");
            }

            F2mFieldElement aF2m = (F2mFieldElement)a;
            F2mFieldElement bF2m = (F2mFieldElement)b;

            if ((aF2m.m != bF2m.m) || (aF2m.k1 != bF2m.k1)
                || (aF2m.k2 != bF2m.k2) || (aF2m.k3 != bF2m.k3))
            {
                throw new ArgumentException("Field elements are not "
                    + "elements of the same field F2m");
            }

            if (aF2m.representation != bF2m.representation)
            {
                // Should never occur
                throw new ArgumentException(
                    "One of the field "
                    + "elements are not elements has incorrect representation");
            }
        }

        public override ECFieldElement Add(
            ECFieldElement b)
        {
            // No check performed here for performance reasons. Instead the
            // elements involved are checked in ECPoint.F2m
            // checkFieldElements(this, b);
            IntArray iarrClone = (IntArray) this.x.Copy();
            F2mFieldElement bF2m = (F2mFieldElement) b;
            iarrClone.AddShifted(bF2m.x, 0);
            return new F2mFieldElement(m, k1, k2, k3, iarrClone);
        }

        public override ECFieldElement Subtract(
            ECFieldElement b)
        {
            // Addition and subtraction are the same in F2m
            return Add(b);
        }

        public override ECFieldElement Multiply(
            ECFieldElement b)
        {
            // Right-to-left comb multiplication in the IntArray
            // Input: Binary polynomials a(z) and b(z) of degree at most m-1
            // Output: c(z) = a(z) * b(z) mod f(z)

            // No check performed here for performance reasons. Instead the
            // elements involved are checked in ECPoint.F2m
            // checkFieldElements(this, b);
            F2mFieldElement bF2m = (F2mFieldElement) b;
            IntArray mult = x.Multiply(bF2m.x, m);
            mult.Reduce(m, new int[]{k1, k2, k3});
            return new F2mFieldElement(m, k1, k2, k3, mult);
        }

        public override ECFieldElement Divide(
            ECFieldElement b)
        {
            // There may be more efficient implementations
            ECFieldElement bInv = b.Invert();
            return Multiply(bInv);
        }

        public override ECFieldElement Negate()
        {
            // -x == x holds for all x in F2m
            return this;
        }

        public override ECFieldElement Square()
        {
            IntArray squared = x.Square(m);
            squared.Reduce(m, new int[]{k1, k2, k3});
            return new F2mFieldElement(m, k1, k2, k3, squared);
        }

        public override ECFieldElement Invert()
        {
            // Inversion in F2m using the extended Euclidean algorithm
            // Input: A nonzero polynomial a(z) of degree at most m-1
            // Output: a(z)^(-1) mod f(z)

            // u(z) := a(z)
            IntArray uz = (IntArray)this.x.Copy();

            // v(z) := f(z)
            IntArray vz = new IntArray(t);
            vz.SetBit(m);
            vz.SetBit(0);
            vz.SetBit(this.k1);
            if (this.representation == Ppb)
            {
                vz.SetBit(this.k2);
                vz.SetBit(this.k3);
            }

            // g1(z) := 1, g2(z) := 0
            IntArray g1z = new IntArray(t);
            g1z.SetBit(0);
            IntArray g2z = new IntArray(t);

            // while u != 0
            while (uz.GetUsedLength() > 0)
//            while (uz.bitLength() > 1)
            {
                // j := deg(u(z)) - deg(v(z))
                int j = uz.BitLength - vz.BitLength;

                // If j < 0 then: u(z) <-> v(z), g1(z) <-> g2(z), j := -j
                if (j < 0)
                {
                    IntArray uzCopy = uz;
                    uz = vz;
                    vz = uzCopy;

                    IntArray g1zCopy = g1z;
                    g1z = g2z;
                    g2z = g1zCopy;

                    j = -j;
                }

                // u(z) := u(z) + z^j * v(z)
                // Note, that no reduction modulo f(z) is required, because
                // deg(u(z) + z^j * v(z)) <= max(deg(u(z)), j + deg(v(z)))
                // = max(deg(u(z)), deg(u(z)) - deg(v(z)) + deg(v(z))
                // = deg(u(z))
                // uz = uz.xor(vz.ShiftLeft(j));
                // jInt = n / 32
                int jInt = j >> 5;
                // jInt = n % 32
                int jBit = j & 0x1F;
                IntArray vzShift = vz.ShiftLeft(jBit);
                uz.AddShifted(vzShift, jInt);

                // g1(z) := g1(z) + z^j * g2(z)
//                g1z = g1z.xor(g2z.ShiftLeft(j));
                IntArray g2zShift = g2z.ShiftLeft(jBit);
                g1z.AddShifted(g2zShift, jInt);
            }
            return new F2mFieldElement(this.m, this.k1, this.k2, this.k3, g2z);
        }

        public override ECFieldElement Sqrt()
        {
            throw new ArithmeticException("Not implemented");
        }

        /**
            * @return the representation of the field
            * <code>F<sub>2<sup>m</sup></sub></code>, either of
            * {@link F2mFieldElement.Tpb} (trinomial
            * basis representation) or
            * {@link F2mFieldElement.Ppb} (pentanomial
            * basis representation).
            */
        public int Representation
        {
            get { return this.representation; }
        }

        /**
            * @return the degree <code>m</code> of the reduction polynomial
            * <code>f(z)</code>.
            */
        public int M
        {
            get { return this.m; }
        }

        /**
            * @return Tpb: The integer <code>k</code> where <code>x<sup>m</sup> +
            * x<sup>k</sup> + 1</code> represents the reduction polynomial
            * <code>f(z)</code>.<br/>
            * Ppb: The integer <code>k1</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.<br/>
            */
        public int K1
        {
            get { return this.k1; }
        }

        /**
            * @return Tpb: Always returns <code>0</code><br/>
            * Ppb: The integer <code>k2</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.<br/>
            */
        public int K2
        {
            get { return this.k2; }
        }

        /**
            * @return Tpb: Always set to <code>0</code><br/>
            * Ppb: The integer <code>k3</code> where <code>x<sup>m</sup> +
            * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
            * represents the reduction polynomial <code>f(z)</code>.<br/>
            */
        public int K3
        {
            get { return this.k3; }
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            F2mFieldElement other = obj as F2mFieldElement;

            if (other == null)
                return false;

            return Equals(other);
        }

        public virtual bool Equals(
            F2mFieldElement other)
        {
            return m == other.m
                && k1 == other.k1
                && k2 == other.k2
                && k3 == other.k3
                && representation == other.representation
                && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return m.GetHashCode()
                ^	k1.GetHashCode()
                ^	k2.GetHashCode()
                ^	k3.GetHashCode()
                ^	representation.GetHashCode()
                ^	base.GetHashCode();
        }
    }
}
