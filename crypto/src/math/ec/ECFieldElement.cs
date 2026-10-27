using System;
using System.Diagnostics;

using Org.BouncyCastle.Math.BinPoly;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC
{
    /// <summary>Base class for elements of the field underlying an elliptic curve.</summary>
    public abstract class ECFieldElement
    {
        /// <summary>Return the value of the element as a BigInteger.</summary>
        /// <returns>The value.</returns>
        public abstract BigInteger ToBigInteger();
        /// <summary>Gets the field name.</summary>
        public abstract string FieldName { get; }
        /// <summary>Gets the field size.</summary>
        public abstract int FieldSize { get; }
        /// <summary>Return the sum of this element and another.</summary>
        /// <param name="b">The other element.</param>
        /// <returns>The sum.</returns>
        public abstract ECFieldElement Add(ECFieldElement b);
        /// <summary>Return this element plus one.</summary>
        /// <returns>The result.</returns>
        public abstract ECFieldElement AddOne();
        /// <summary>Return the difference of this element and another.</summary>
        /// <param name="b">The element to subtract.</param>
        /// <returns>The difference.</returns>
        public abstract ECFieldElement Subtract(ECFieldElement b);
        /// <summary>Return the product of this element and another.</summary>
        /// <param name="b">The other element.</param>
        /// <returns>The product.</returns>
        public abstract ECFieldElement Multiply(ECFieldElement b);
        /// <summary>Return the quotient of this element and another.</summary>
        /// <param name="b">The divisor.</param>
        /// <returns>The quotient.</returns>
        public abstract ECFieldElement Divide(ECFieldElement b);
        /// <summary>Return the negation of this element.</summary>
        /// <returns>The negation.</returns>
        public abstract ECFieldElement Negate();
        /// <summary>Return the square of this element.</summary>
        /// <returns>The square.</returns>
        public abstract ECFieldElement Square();
        /// <summary>Return the multiplicative inverse of this element.</summary>
        /// <returns>The inverse.</returns>
        public abstract ECFieldElement Invert();
        /// <summary>Return a square root of this element, if there is one.</summary>
        /// <returns>A square root, or null if there is none.</returns>
        public abstract ECFieldElement Sqrt();

        /// <summary>Gets the bit length.</summary>
        public virtual int BitLength => ToBigInteger().BitLength;

        /// <summary>Gets a value indicating whether this is one.</summary>
        public virtual bool IsOne => BitLength == 1;

        /// <summary>Gets a value indicating whether this is zero.</summary>
        public virtual bool IsZero => 0 == ToBigInteger().SignValue;

        /// <summary>Calculate this * b - x * y.</summary>
        /// <param name="b">The second factor of the first product.</param>
        /// <param name="x">The first factor of the second product.</param>
        /// <param name="y">The second factor of the second product.</param>
        /// <returns>The result.</returns>
        public virtual ECFieldElement MultiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y) =>
            Multiply(b).Subtract(x.Multiply(y));

        /// <summary>Calculate this * b + x * y.</summary>
        /// <param name="b">The second factor of the first product.</param>
        /// <param name="x">The first factor of the second product.</param>
        /// <param name="y">The second factor of the second product.</param>
        /// <returns>The result.</returns>
        public virtual ECFieldElement MultiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y) =>
            Multiply(b).Add(x.Multiply(y));

        /// <summary>Calculate this^2 - x * y.</summary>
        /// <param name="x">The first factor of the product.</param>
        /// <param name="y">The second factor of the product.</param>
        /// <returns>The result.</returns>
        public virtual ECFieldElement SquareMinusProduct(ECFieldElement x, ECFieldElement y) =>
            Square().Subtract(x.Multiply(y));

        /// <summary>Calculate this^2 + x * y.</summary>
        /// <param name="x">The first factor of the product.</param>
        /// <param name="y">The second factor of the product.</param>
        /// <returns>The result.</returns>
        public virtual ECFieldElement SquarePlusProduct(ECFieldElement x, ECFieldElement y) =>
            Square().Add(x.Multiply(y));

        /// <summary>Raise this element to the power 2^pow, by repeated squaring.</summary>
        /// <param name="pow">The number of squarings.</param>
        /// <returns>The result.</returns>
        public virtual ECFieldElement SquarePow(int pow)
        {
            ECFieldElement r = this;
            for (int i = 0; i < pow; ++i)
            {
                r = r.Square();
            }
            return r;
        }

        /// <summary>Determine whether the least significant bit of the element is set.</summary>
        /// <returns>true if the bit is set, false otherwise.</returns>
        public virtual bool TestBitZero() => ToBigInteger().TestBit(0);

        /// <inheritdoc/>
        public override bool Equals(object obj) => Equals(obj as ECFieldElement);

        /// <summary>Determine whether this element is equal to another.</summary>
        /// <param name="other">The element to compare with.</param>
        /// <returns>true if the elements are equal, false otherwise.</returns>
        public virtual bool Equals(ECFieldElement other)
        {
            if (this == other)
                return true;

            return other != null
                && ToBigInteger().Equals(other.ToBigInteger());
        }

        /// <inheritdoc/>
        public override int GetHashCode() => ToBigInteger().GetHashCode();

        /// <inheritdoc/>
        public override string ToString() => ToBigInteger().ToString(16);

        /// <summary>Return the encoded.</summary>
        public virtual byte[] GetEncoded()
        {
            byte[] buf = new byte[GetEncodedLength()];
            EncodeTo(buf, 0);
            return buf;
        }

        /// <summary>Return the encoded length.</summary>
        public virtual int GetEncodedLength() => (FieldSize + 7) / 8;

        /// <summary>Write the fixed-length encoding of this element.</summary>
        /// <param name="buf">The buffer to write to.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which to write.</param>
        public virtual void EncodeTo(byte[] buf, int off) =>
            BigIntegers.AsUnsignedByteArray(ToBigInteger(), buf, off, GetEncodedLength());

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Write the fixed-length encoding of this element.</summary>
        /// <param name="buf">The buffer to write to.</param>
        public virtual void EncodeTo(Span<byte> buf) =>
            BigIntegers.AsUnsignedByteArray(ToBigInteger(), buf[..GetEncodedLength()]);
#endif
    }

    /// <summary>Base class for elements of a prime field.</summary>
    public abstract class AbstractFpFieldElement
        : ECFieldElement
    {
    }

    /// <summary>An element of a prime field.</summary>
    public class FpFieldElement
        : AbstractFpFieldElement
    {
        private readonly BigInteger m_q, m_r, m_x;

        internal static BigInteger CalculateResidue(BigInteger p)
        {
            int bitLength = p.BitLength;
            if (bitLength >= 96)
            {
                BigInteger firstWord = p.ShiftRight(bitLength - 64);

                if (firstWord.LongValue == -1L)
                    return BigInteger.One.ShiftLeft(bitLength).Subtract(p);

                if ((bitLength & 7) == 0)
                    return BigInteger.One.ShiftLeft(bitLength << 1).Divide(p).Negate();
            }
            return null;
        }

        internal FpFieldElement(BigInteger q, BigInteger r, BigInteger x)
        {
            m_q = q;
            m_r = r;
            m_x = x;
        }

        /// <inheritdoc/>
        public override BigInteger ToBigInteger() => m_x;

        /// <inheritdoc/>
        public override string FieldName => "Fp";

        /// <inheritdoc/>
        public override int FieldSize => m_q.BitLength;

        /// <summary>Gets the q.</summary>
        public BigInteger Q => m_q;

        /// <inheritdoc/>
        public override ECFieldElement Add(ECFieldElement b) =>
            new FpFieldElement(m_q, m_r, ModAdd(m_x, b.ToBigInteger()));

        /// <inheritdoc/>
        public override ECFieldElement AddOne()
        {
            BigInteger x2 = m_x.Add(BigInteger.One);
            if (x2.CompareTo(m_q) == 0)
            {
                x2 = BigInteger.Zero;
            }
            return new FpFieldElement(m_q, m_r, x2);
        }

        /// <inheritdoc/>
        public override ECFieldElement Subtract(ECFieldElement b) =>
            new FpFieldElement(m_q, m_r, ModSubtract(m_x, b.ToBigInteger()));

        /// <inheritdoc/>
        public override ECFieldElement Multiply(ECFieldElement b) =>
            new FpFieldElement(m_q, m_r, ModMult(m_x, b.ToBigInteger()));

        /// <inheritdoc/>
        public override ECFieldElement MultiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = m_x, bx = b.ToBigInteger(), xx = x.ToBigInteger(), yx = y.ToBigInteger();
            BigInteger ab = ax.Multiply(bx);
            BigInteger xy = xx.Multiply(yx);
            return new FpFieldElement(m_q, m_r, ModReduce(ab.Subtract(xy)));
        }

        /// <inheritdoc/>
        public override ECFieldElement MultiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = m_x, bx = b.ToBigInteger(), xx = x.ToBigInteger(), yx = y.ToBigInteger();
            BigInteger ab = ax.Multiply(bx);
            BigInteger xy = xx.Multiply(yx);
            BigInteger sum = ab.Add(xy);
            if (m_r != null && m_r.SignValue < 0 && sum.BitLength > (m_q.BitLength << 1))
            {
                sum = sum.Subtract(m_q.ShiftLeft(m_q.BitLength));
            }
            return new FpFieldElement(m_q, m_r, ModReduce(sum));
        }

        /// <inheritdoc/>
        public override ECFieldElement Divide(ECFieldElement b) =>
            new FpFieldElement(m_q, m_r, ModMult(m_x, ModInverse(b.ToBigInteger())));

        /// <inheritdoc/>
        public override ECFieldElement Negate() =>
            m_x.SignValue == 0 ? this : new FpFieldElement(m_q, m_r, m_q.Subtract(m_x));

        /// <inheritdoc/>
        public override ECFieldElement Square() =>
            new FpFieldElement(m_q, m_r, ModMult(m_x, m_x));

        /// <inheritdoc/>
        public override ECFieldElement SquareMinusProduct(ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = m_x, xx = x.ToBigInteger(), yx = y.ToBigInteger();
            BigInteger aa = ax.Multiply(ax);
            BigInteger xy = xx.Multiply(yx);
            return new FpFieldElement(m_q, m_r, ModReduce(aa.Subtract(xy)));
        }

        /// <inheritdoc/>
        public override ECFieldElement SquarePlusProduct(ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = m_x, xx = x.ToBigInteger(), yx = y.ToBigInteger();
            BigInteger aa = ax.Multiply(ax);
            BigInteger xy = xx.Multiply(yx);
            BigInteger sum = aa.Add(xy);
            if (m_r != null && m_r.SignValue < 0 && sum.BitLength > (m_q.BitLength << 1))
            {
                sum = sum.Subtract(m_q.ShiftLeft(m_q.BitLength));
            }
            return new FpFieldElement(m_q, m_r, ModReduce(sum));
        }

        /// <inheritdoc/>
        public override ECFieldElement Invert()
        {
            // TODO Modular inversion can be faster for a (Generalized) Mersenne Prime.
            return new FpFieldElement(m_q, m_r, ModInverse(m_x));
        }

        /// <summary>Return a square root.</summary>
        /// <remarks>
        /// The routine verifies that the calculation returns a valid root; if none exists it returns <c>null</c>.
        /// </remarks>
        public override ECFieldElement Sqrt()
        {
            if (IsZero || IsOne)
                return this;

            if (!m_q.TestBit(0))
                throw new NotImplementedException("even value of q");

            if (m_q.TestBit(1)) // q == 4m + 3
            {
                BigInteger e = m_q.ShiftRight(2).Add(BigInteger.One);
                return CheckSqrt(new FpFieldElement(m_q, m_r, m_x.ModPow(e, m_q)));
            }

            if (m_q.TestBit(2)) // q == 8m + 5
            {
                BigInteger t1 = m_x.ModPow(m_q.ShiftRight(3), m_q);
                BigInteger t2 = ModMult(t1, m_x);
                BigInteger t3 = ModMult(t2, t1);

                if (t3.Equals(BigInteger.One))
                    return CheckSqrt(new FpFieldElement(m_q, m_r, t2));

                // TODO This is constant and could be precomputed
                BigInteger t4 = BigInteger.Two.ModPow(m_q.ShiftRight(2), m_q);

                BigInteger y = ModMult(t2, t4);

                return CheckSqrt(new FpFieldElement(m_q, m_r, y));
            }

            // q == 8m + 1

            BigInteger legendreExponent = m_q.ShiftRight(1);
            if (!(m_x.ModPow(legendreExponent, m_q).Equals(BigInteger.One)))
                return null;

            BigInteger X = m_x;
            BigInteger fourX = ModDouble(ModDouble(X)); ;

            BigInteger k = legendreExponent.Add(BigInteger.One), qMinusOne = m_q.Subtract(BigInteger.One);

            BigInteger U, V;
            do
            {
                BigInteger P;
                do
                {
                    P = BigInteger.Arbitrary(m_q.BitLength);
                }
                while (P.CompareTo(m_q) >= 0
                    || !ModReduce(P.Multiply(P).Subtract(fourX)).ModPow(legendreExponent, m_q).Equals(qMinusOne));

                BigInteger[] result = LucasSequence(P, X, k);
                U = result[0];
                V = result[1];

                if (ModMult(V, V).Equals(fourX))
                    return new FpFieldElement(m_q, m_r, ModHalfAbs(V));
            }
            while (U.Equals(BigInteger.One) || U.Equals(qMinusOne));

            return null;
        }

        private ECFieldElement CheckSqrt(ECFieldElement z) => z.Square().Equals(this) ? z : null;

        private BigInteger[] LucasSequence(BigInteger P, BigInteger Q, BigInteger k)
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

        /// <summary>Add two values modulo the field prime.</summary>
        /// <param name="x1">The first value.</param>
        /// <param name="x2">The second value.</param>
        /// <returns>The sum modulo the prime.</returns>
        protected virtual BigInteger ModAdd(BigInteger x1, BigInteger x2)
        {
            BigInteger x3 = x1.Add(x2);
            if (x3.CompareTo(m_q) >= 0)
            {
                x3 = x3.Subtract(m_q);
            }
            return x3;
        }

        /// <summary>Double a value modulo the field prime.</summary>
        /// <param name="x">The value.</param>
        /// <returns>The result.</returns>
        protected virtual BigInteger ModDouble(BigInteger x)
        {
            BigInteger _2x = x.ShiftLeft(1);
            if (_2x.CompareTo(m_q) >= 0)
            {
                _2x = _2x.Subtract(m_q);
            }
            return _2x;
        }

        /// <summary>Halve a value modulo the field prime.</summary>
        /// <param name="x">The value.</param>
        /// <returns>The result.</returns>
        protected virtual BigInteger ModHalf(BigInteger x)
        {
            if (x.TestBit(0))
            {
                x = m_q.Add(x);
            }
            return x.ShiftRight(1);
        }

        /// <summary>
        /// Halve a value modulo the field prime, returning the representative that is less than half the prime.
        /// </summary>
        /// <param name="x">The value.</param>
        /// <returns>The result.</returns>
        protected virtual BigInteger ModHalfAbs(BigInteger x)
        {
            if (x.TestBit(0))
            {
                x = m_q.Subtract(x);
            }
            return x.ShiftRight(1);
        }

        /// <summary>Invert a value modulo the field prime.</summary>
        /// <param name="x">The value.</param>
        /// <returns>The inverse.</returns>
        protected virtual BigInteger ModInverse(BigInteger x) => BigIntegers.ModOddInverse(m_q, x);

        /// <summary>Multiply two values modulo the field prime.</summary>
        /// <param name="x1">The first value.</param>
        /// <param name="x2">The second value.</param>
        /// <returns>The product modulo the prime.</returns>
        protected virtual BigInteger ModMult(BigInteger x1, BigInteger x2) => ModReduce(x1.Multiply(x2));

        /// <summary>Reduce a value modulo the field prime.</summary>
        /// <param name="x">The value.</param>
        /// <returns>The reduced value.</returns>
        protected virtual BigInteger ModReduce(BigInteger x)
        {
            if (m_r == null)
            {
                x = x.Mod(m_q);
            }
            else
            {
                bool negative = x.SignValue < 0;
                if (negative)
                {
                    x = x.Abs();
                }
                int qLen = m_q.BitLength;
                if (m_r.SignValue > 0)
                {
                    BigInteger qMod = BigInteger.One.ShiftLeft(qLen);
                    bool rIsOne = m_r.Equals(BigInteger.One);
                    while (x.BitLength > (qLen + 1))
                    {
                        BigInteger u = x.ShiftRight(qLen);
                        BigInteger v = x.Remainder(qMod);
                        if (!rIsOne)
                        {
                            u = u.Multiply(m_r);
                        }
                        x = u.Add(v);
                    }
                }
                else
                {
                    int d = ((qLen - 1) & 31) + 1;
                    BigInteger mu = m_r.Negate();
                    BigInteger u = mu.Multiply(x.ShiftRight(qLen - d));
                    BigInteger quot = u.ShiftRight(qLen + d);
                    BigInteger v = quot.Multiply(m_q);
                    BigInteger bk1 = BigInteger.One.ShiftLeft(qLen + d);
                    v = v.Remainder(bk1);
                    x = x.Remainder(bk1);
                    x = x.Subtract(v);
                    if (x.SignValue < 0)
                    {
                        x = x.Add(bk1);
                    }
                }
                while (x.CompareTo(m_q) >= 0)
                {
                    x = x.Subtract(m_q);
                }
                if (negative && x.SignValue != 0)
                {
                    x = m_q.Subtract(x);
                }
            }
            return x;
        }

        /// <summary>Subtract two values modulo the field prime.</summary>
        /// <param name="x1">The first value.</param>
        /// <param name="x2">The second value.</param>
        /// <returns>The difference modulo the prime.</returns>
        protected virtual BigInteger ModSubtract(BigInteger x1, BigInteger x2)
        {
            BigInteger x3 = x1.Subtract(x2);
            if (x3.SignValue < 0)
            {
                x3 = x3.Add(m_q);
            }
            return x3;
        }

        /// <inheritdoc/>
        public override bool Equals(object obj) => Equals(obj as FpFieldElement);

        /// <summary>Determine whether this element is equal to another.</summary>
        /// <param name="other">The element to compare with.</param>
        /// <returns>true if the elements are equal, false otherwise.</returns>
        public virtual bool Equals(FpFieldElement other)
        {
            if (this == other)
                return true;

            return other != null
                && m_q.Equals(other.m_q)
                && m_x.Equals(other.m_x);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return HashCode.Combine(m_q, m_x);
#else
            return m_q.GetHashCode() ^ m_x.GetHashCode();
#endif
        }
    }

    /// <summary>Base class for elements of a binary field.</summary>
    public abstract class AbstractF2mFieldElement
        :   ECFieldElement
    {
        /// <summary>
        /// Compute a solution of the quadratic equation z^2 + z = this (the half-trace), for fields of odd degree.
        /// </summary>
        /// <returns>The half-trace.</returns>
        public virtual ECFieldElement HalfTrace()
        {
            int m = FieldSize;
            if ((m & 1) == 0)
                throw new InvalidOperationException("Half-trace only defined for odd m");

            //ECFieldElement ht = this;
            //for (int i = 1; i < m; i += 2)
            //{
            //    ht = ht.SquarePow(2).Add(this);
            //}

            int n = (m + 1) >> 1;
            int k = Integers.BitLength(n) - 1;
            int nk = 1;

            ECFieldElement ht = this;
            while (k > 0)
            {
                ht = ht.SquarePow(nk << 1).Add(ht);
                nk = n >> --k;
                if (0 != (nk & 1))
                {
                    ht = ht.SquarePow(2).Add(this);
                }
            }

            return ht;
        }

        /// <summary>Gets a value indicating whether this has fast trace.</summary>
        public virtual bool HasFastTrace => false;

        /// <summary>Compute the trace of this element.</summary>
        /// <returns>The trace, 0 or 1.</returns>
        public virtual int Trace()
        {
            int m = FieldSize;

            //ECFieldElement tr = this;
            //for (int i = 1; i < m; ++i)
            //{
            //    tr = tr.Square().Add(this);
            //}

            int k = Integers.BitLength(m) - 1;
            int mk = 1;

            ECFieldElement tr = this;
            while (k > 0)
            {
                tr = tr.SquarePow(mk).Add(tr);
                mk = m >> --k;
                if (0 != (mk & 1))
                {
                    tr = tr.Square().Add(this);
                }
            }

            if (tr.IsZero)
                return 0;
            if (tr.IsOne)
                return 1;
            throw new InvalidOperationException("Internal error in trace calculation");
        }
    }

    /// <summary>
    /// Class representing the elements of the finite field F2m in polynomial basis (PB) representation.
    /// </summary>
    /// <remarks>
    /// Both trinomial (Tpb) and pentanomial (Ppb) polynomial basis representations are supported. Gaussian normal basis (GNB)
    /// representation is not supported.
    /// </remarks>
    public class F2mFieldElement
        :   AbstractF2mFieldElement
    {
        /// <summary>
        /// Indicates gaussian normal basis representation (GNB). Number chosen according to X9.62. GNB is not
        /// implemented at present.
        /// </summary>
        public const int Gnb = 1;

        /// <summary>
        /// Indicates trinomial basis representation (Tpb). Number chosen according to X9.62.
        /// </summary>
        public const int Tpb = 2;

        /// <summary>
        /// Indicates pentanomial basis representation (Ppb). Number chosen according to X9.62.
        /// </summary>
        public const int Ppb = 3;

        private readonly F2mFieldData m_f2mFieldData;
        internal readonly ulong[] m_x;

        internal F2mFieldElement(F2mFieldData f2mFieldData, ulong[] x)
        {
            m_f2mFieldData = f2mFieldData ?? throw new ArgumentNullException(nameof(f2mFieldData));
            m_x = x ?? throw new ArgumentNullException(nameof(x));
        }

        /// <inheritdoc/>
        public override int BitLength => BinPolys.BitLengthVar(m_x.Length, m_x, 0);

        /// <inheritdoc/>
        public override bool IsOne => BinPolys.EqualToOne(m_x.Length, m_x, 0) != 0UL;

        /// <inheritdoc/>
        public override bool IsZero => BinPolys.EqualToZero(m_x.Length, m_x, 0) != 0UL;

        /// <inheritdoc/>
        public override bool TestBitZero() => (m_x[0] & 1UL) != 0UL;

        /// <inheritdoc/>
        public override BigInteger ToBigInteger() => Nat.ToBigInteger64(m_x.Length, m_x);

        /// <inheritdoc/>
        public override string FieldName => "F2m";

        /// <inheritdoc/>
        public override int FieldSize => M;

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
        public static void CheckFieldElements(ECFieldElement a, ECFieldElement b)
        {
            if (!(a is F2mFieldElement aF2m) || !(b is F2mFieldElement bF2m))
                throw new ArgumentException("Field elements are not both instances of F2mFieldElement");

            if (!F2mFieldData.Equals(aF2m.m_f2mFieldData, bF2m.m_f2mFieldData))
                throw new ArgumentException("Field elements are not elements of the same field F2m");
        }

        /// <inheritdoc/>
        public override ECFieldElement Add(ECFieldElement b)
        {
            F2mFieldElement bF2m = (F2mFieldElement)b;
            int size = m_x.Length;
            ulong[] z = BinPolys.Create(size);
            BinPolys.Add(size, m_x, 0, bF2m.m_x, 0, z, 0);
            return new F2mFieldElement(m_f2mFieldData, z);
        }

        /// <inheritdoc/>
        public override ECFieldElement AddOne()
        {
            ulong[] z = BinPolys.Create(m_x.Length);
            BinPolys.Copy(m_x.Length, m_x, 0, z, 0);
            z[0] ^= 1UL;
            return new F2mFieldElement(m_f2mFieldData, z);
        }

        /// <inheritdoc/>
        public override ECFieldElement Subtract(ECFieldElement b) => Add(b);

        /// <inheritdoc/>
        public override ECFieldElement Multiply(ECFieldElement b)
        {
            F2mFieldElement bF2m = (F2mFieldElement)b;
            ulong[] z = BinPolys.Create(m_x.Length);
            m_f2mFieldData._mul.Multiply(m_x, 0, bF2m.m_x, 0, z, 0);
            return new F2mFieldElement(m_f2mFieldData, z);
        }

        /// <inheritdoc/>
        public override ECFieldElement MultiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y) =>
            MultiplyPlusProduct(b, x, y);

        /// <inheritdoc/>
        public override ECFieldElement Divide(ECFieldElement b)
        {
            // There may be more efficient implementations
            ECFieldElement bInv = b.Invert();
            return Multiply(bInv);
        }

        /// <inheritdoc/>
        public override ECFieldElement Negate()
        {
            // -x == x holds for all x in F2m
            return this;
        }

        /// <inheritdoc/>
        public override ECFieldElement Square()
        {
            int size = m_x.Length;
            ulong[] z = BinPolys.Create(size);
            m_f2mFieldData._mul.Square(m_x, 0, z, 0);
            return new F2mFieldElement(m_f2mFieldData, z);
        }

        /// <inheritdoc/>
        public override ECFieldElement SquareMinusProduct(ECFieldElement x, ECFieldElement y) =>
            SquarePlusProduct(x, y);

        /// <inheritdoc/>
        public override ECFieldElement SquarePow(int pow)
        {
            if (pow < 1)
                return this;

            int size = m_x.Length;
            ulong[] z = BinPolys.Create(size);
            m_f2mFieldData._mul.SquareN(m_x, 0, pow, z, 0);
            return new F2mFieldElement(m_f2mFieldData, z);
        }

        /// <inheritdoc/>
        public override ECFieldElement Invert()
        {
            // TODO Intentional fast-path in otherwise constant-time implementation (for performance) - review.
            if (BitLength <= 1)
                return this;

            ulong[] z = BinPolys.Create(m_x.Length);
            m_f2mFieldData._inv.Invert(m_x, 0, z, 0);
            return new F2mFieldElement(m_f2mFieldData, z);
        }

        /// <inheritdoc/>
        public override ECFieldElement Sqrt()
        {
            // TODO Intentional fast-path in otherwise constant-time implementation (for performance) - review.
            if (BitLength <= 1)
                return this;

            return SquarePow(M - 1);
        }

        /// <summary>Gets the representation.</summary>
        public int Representation => m_f2mFieldData._ks.Length == 1 ? Tpb : Ppb;

        /// <summary>Gets the m.</summary>
        public int M => m_f2mFieldData._m;

        /// <summary>Gets the k 1.</summary>
        public int K1 => m_f2mFieldData.K1;

        /// <summary>Gets the k 2.</summary>
        public int K2 => m_f2mFieldData.K2;

        /// <summary>Gets the k 3.</summary>
        public int K3 => m_f2mFieldData.K3;

        /// <inheritdoc/>
        public override bool Equals(object obj) => Equals(obj as F2mFieldElement);

        /// <summary>Determine whether this element is equal to another.</summary>
        /// <param name="other">The element to compare with.</param>
        /// <returns>true if the elements are equal, false otherwise.</returns>
        public virtual bool Equals(F2mFieldElement other)
        {
            if (this == other)
                return true;

            return other != null
                && F2mFieldData.Equals(m_f2mFieldData, other.m_f2mFieldData)
                && m_x.Length == other.m_x.Length
                && BinPolys.EqualTo(m_x.Length, m_x, 0, other.m_x, 0) != 0UL;
        }

        /// <inheritdoc/>
        public override int GetHashCode() => Arrays.GetHashCode(m_x) ^ F2mFieldData.GetHashCode(m_f2mFieldData);
    }
}
