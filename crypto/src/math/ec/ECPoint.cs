using System;
using System.Collections;
using System.Diagnostics;

using Org.BouncyCastle.Math.EC.Multiplier;

namespace Org.BouncyCastle.Math.EC
{
    /**
     * base class for points on elliptic curves.
     */
    public abstract class ECPoint
    {
        protected static ECFieldElement[] EMPTY_ZS = new ECFieldElement[0];

        protected static ECFieldElement[] GetInitialZCoords(ECCurve curve)
        {
            // Cope with null curve, most commonly used by implicitlyCa
            int coord = null == curve ? ECCurve.COORD_AFFINE : curve.CoordinateSystem;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                case ECCurve.COORD_LAMBDA_AFFINE:
                    return EMPTY_ZS;
                default:
                    break;
            }

            ECFieldElement one = curve.FromBigInteger(BigInteger.One);

            switch (coord)
            {
                case ECCurve.COORD_HOMOGENEOUS:
                case ECCurve.COORD_JACOBIAN:
                case ECCurve.COORD_LAMBDA_PROJECTIVE:
                    return new ECFieldElement[] { one };
                case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
                    return new ECFieldElement[] { one, one, one };
                case ECCurve.COORD_JACOBIAN_MODIFIED:
                    return new ECFieldElement[] { one, curve.A };
                default:
                    throw new ArgumentException("unknown coordinate system");
            }
        }

        protected internal readonly ECCurve m_curve;
        protected internal readonly ECFieldElement m_x, m_y;
        protected internal readonly ECFieldElement[] m_zs;
        protected internal readonly bool m_withCompression;

        protected internal PreCompInfo m_preCompInfo = null;

        protected ECPoint(
            ECCurve			curve,
            ECFieldElement	x,
            ECFieldElement	y,
            bool			withCompression)
        {
            this.m_curve = curve;
            this.m_x = x;
            this.m_y = y;
            this.m_withCompression = withCompression;
        }

        protected ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
        {
            this.m_curve = curve;
            this.m_x = x;
            this.m_y = y;
            this.m_zs = zs;
        }

        public virtual ECCurve Curve
        {
            get { return m_curve; }
        }

        protected virtual int CurveCoordinateSystem
        {
            get
            {
                // Cope with null curve, most commonly used by implicitlyCa
                return null == m_curve ? ECCurve.COORD_AFFINE : m_curve.CoordinateSystem;
            }
        }

        public virtual ECFieldElement X
        {
            get { return m_x; }
        }

        public virtual ECFieldElement Y
        {
            get { return m_y; }
        }

        public virtual ECFieldElement GetZCoord(int index)
        {
            return (index < 0 || index >= m_zs.Length) ? null : m_zs[index];
        }

        public virtual ECFieldElement[] GetZCoords()
        {
            int zsLen = m_zs.Length;
            if (zsLen == 0)
            {
                return m_zs;
            }
            ECFieldElement[] copy = new ECFieldElement[zsLen];
            Array.Copy(m_zs, 0, copy, 0, zsLen);
            return copy;
        }

        protected virtual void CheckNormalized()
        {
            if (!IsNormalized())
                throw new InvalidOperationException("point not in normal form");
        }

        public virtual bool IsNormalized()
        {
            int coord = this.CurveCoordinateSystem;

            return coord == ECCurve.COORD_AFFINE
                || coord == ECCurve.COORD_LAMBDA_AFFINE
                || IsInfinity;
                //|| zs[0].isOne();
        }

        /**
         * Normalization ensures that any projective coordinate is 1, and therefore that the x, y
         * coordinates reflect those of the equivalent point in an affine coordinate system.
         * 
         * @return a new ECPoint instance representing the same point, but with normalized coordinates
         */
        public virtual ECPoint Normalize()
        {
            if (this.IsInfinity)
            {
                return this;
            }

            switch (this.CurveCoordinateSystem)
            {
                case ECCurve.COORD_AFFINE:
                case ECCurve.COORD_LAMBDA_AFFINE:
                {
                    return this;
                }
                default:
                {
                    ECFieldElement Z1 = GetZCoord(0);
                    if (Z1.IsOne)
                    {
                        return this;
                    }

                    return Normalize(Z1.Invert());
                }
            }
        }

        internal virtual ECPoint Normalize(ECFieldElement zInv)
        {
            throw new InvalidOperationException("not a projective coordinate system");

            //switch (this.CurveCoordinateSystem)
            //{
            //    case ECCurve.COORD_HOMOGENEOUS:
            //    case ECCurve.COORD_LAMBDA_PROJECTIVE:
            //    {
            //        return CreateScaledPoint(zInv, zInv);
            //    }
            //    case ECCurve.COORD_JACOBIAN:
            //    case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
            //    case ECCurve.COORD_JACOBIAN_MODIFIED:
            //    {
            //        ECFieldElement zInv2 = zInv.Square(), zInv3 = zInv2.Multiply(zInv);
            //        return CreateScaledPoint(zInv2, zInv3);
            //    }
            //    default:
            //    {
            //        throw new InvalidOperationException("not a projective coordinate system");
            //    }
            //}
        }

        public bool IsInfinity
        {
            get { return m_x == null && m_y == null; }
        }

        public bool IsCompressed
        {
            get { return m_withCompression; }
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as ECPoint);
        }

        public virtual bool Equals(ECPoint other)
        {
            if (this == other)
                return true;
            if (null == other)
                return false;

            bool i1 = IsInfinity, i2 = other.IsInfinity;
            if (i1 || i2)
            {
                return i1 && i2;
            }

            return X.Equals(other.X) && Y.Equals(other.Y);
        }

        public override int GetHashCode()
        {
            int hc = 0;
            if (!IsInfinity)
            {
                hc ^= X.GetHashCode() * 17;
                hc ^= Y.GetHashCode() * 257;
            }
            return hc;
        }

        public virtual byte[] GetEncoded()
        {
            return GetEncoded(m_withCompression);
        }

        public abstract byte[] GetEncoded(bool compressed);

        protected internal abstract bool CompressionYTilde { get; }

        public abstract ECPoint Add(ECPoint b);
        public abstract ECPoint Subtract(ECPoint b);
        public abstract ECPoint Negate();

        public virtual ECPoint TimesPow2(int e)
        {
            if (e < 0)
                throw new ArgumentException("cannot be negative", "e");

            ECPoint p = this;
            while (--e >= 0)
            {
                p = p.Twice();
            }
            return p;
        }

        public abstract ECPoint Twice();
        public abstract ECPoint Multiply(BigInteger b);

        public virtual ECPoint TwicePlus(ECPoint b)
        {
            return Twice().Add(b);
        }

        public virtual ECPoint ThreeTimes()
        {
            return TwicePlus(this);
        }
    }

    public abstract class ECPointBase
        : ECPoint
    {
        protected internal ECPointBase(
            ECCurve			curve,
            ECFieldElement	x,
            ECFieldElement	y,
            bool			withCompression)
            : base(curve, x, y, withCompression)
        {
        }

        /**
         * return the field element encoded with point compression. (S 4.3.6)
         */
        public override byte[] GetEncoded(bool compressed)
        {
            if (this.IsInfinity)
            {
                return new byte[1];
            }

            ECPoint normed = Normalize();

            byte[] X = normed.X.GetEncoded();

            if (compressed)
            {
                byte[] PO = new byte[X.Length + 1];
                PO[0] = (byte)(normed.CompressionYTilde ? 0x03 : 0x02);
                Array.Copy(X, 0, PO, 1, X.Length);
                return PO;
            }

            byte[] Y = normed.Y.GetEncoded();

            {
                byte[] PO = new byte[X.Length + Y.Length + 1];
                PO[0] = 0x04;
                Array.Copy(X, 0, PO, 1, X.Length);
                Array.Copy(Y, 0, PO, X.Length + 1, Y.Length);
                return PO;
            }
        }

        /**
         * Multiplies this <code>ECPoint</code> by the given number.
         * @param k The multiplicator.
         * @return <code>k * this</code>.
         */
        public override ECPoint Multiply(
            BigInteger k)
        {
            if (k.SignValue < 0)
                throw new ArgumentException("The multiplicator cannot be negative", "k");

            if (this.IsInfinity)
                return this;

            if (k.SignValue == 0)
                return Curve.Infinity;

            return Curve.GetMultiplier().Multiply(this, k);
        }
    }

    /**
     * Elliptic curve points over Fp
     */
    public class FpPoint
        : ECPointBase
    {
        /**
         * Create a point which encodes with point compression.
         *
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         */
        public FpPoint(
            ECCurve			curve,
            ECFieldElement	x,
            ECFieldElement	y)
            : this(curve, x, y, false)
        {
        }

        /**
         * Create a point that encodes with or without point compresion.
         *
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         * @param withCompression if true encode with point compression
         */
        public FpPoint(
            ECCurve			curve,
            ECFieldElement	x,
            ECFieldElement	y,
            bool			withCompression)
            : base(curve, x, y, withCompression)
        {
            if ((x == null) != (y == null))
                throw new ArgumentException("Exactly one of the field elements is null");
        }

        protected internal override bool CompressionYTilde
        {
            get { return this.Y.TestBitZero(); }
        }

        // B.3 pg 62
        public override ECPoint Add(
            ECPoint b)
        {
            if (this.IsInfinity)
            {
                return b;
            }
            if (b.IsInfinity)
            {
                return this;
            }
            if (this == b)
            {
                return Twice();
            }

            ECFieldElement X1 = this.X, Y1 = this.Y;
            ECFieldElement X2 = b.X, Y2 = b.Y;

            ECFieldElement dx = X2.Subtract(X1), dy = Y2.Subtract(Y1);

            if (dx.IsZero)
            {
                if (dy.IsZero)
                {
                    // this == b, i.e. this must be doubled
                    return Twice();
                }

                // this == -b, i.e. the result is the point at infinity
                return Curve.Infinity;
            }

            ECFieldElement gamma = dy.Divide(dx);
            ECFieldElement X3 = gamma.Square().Subtract(X1).Subtract(X2);
            ECFieldElement Y3 = gamma.Multiply(X1.Subtract(X3)).Subtract(Y1);

            return new FpPoint(Curve, X3, Y3, IsCompressed);
        }

        // B.3 pg 62
        public override ECPoint Twice()
        {
            if (this.IsInfinity)
            {
                return this;
            }

            ECFieldElement Y1 = this.Y;
            if (Y1.IsZero) 
            {
                return Curve.Infinity;
            }

            ECFieldElement X1 = this.X;

            ECFieldElement X1Squared = X1.Square();
            ECFieldElement gamma = Three(X1Squared).Add(this.Curve.A).Divide(Two(Y1));
            ECFieldElement X3 = gamma.Square().Subtract(Two(X1));
            ECFieldElement Y3 = gamma.Multiply(X1.Subtract(X3)).Subtract(Y1);

            return new FpPoint(Curve, X3, Y3, IsCompressed);
        }

        public override ECPoint TwicePlus(ECPoint b)
        {
            if (this == b)
            {
                return ThreeTimes();
            }
            if (this.IsInfinity)
            {
                return b;
            }
            if (b.IsInfinity)
            {
                return Twice();
            }

            ECFieldElement Y1 = this.Y;
            if (Y1.IsZero)
            {
                return b;
            }

            ECFieldElement X1 = this.X;
            ECFieldElement X2 = b.X, Y2 = b.Y;

            ECFieldElement dx = X2.Subtract(X1), dy = Y2.Subtract(Y1);

            if (dx.IsZero)
            {
                if (dy.IsZero)
                {
                    // this == b i.e. the result is 3P
                    return ThreeTimes();
                }

                // this == -b, i.e. the result is P
                return this;
            }

            /*
             * Optimized calculation of 2P + Q, as described in "Trading Inversions for
             * Multiplications in Elliptic Curve Cryptography", by Ciet, Joye, Lauter, Montgomery.
             */

            ECFieldElement X = dx.Square(), Y = dy.Square();
            ECFieldElement d = X.Multiply(Two(X1).Add(X2)).Subtract(Y);
            if (d.IsZero)
            {
                return Curve.Infinity;
            }

            ECFieldElement D = d.Multiply(dx);
            ECFieldElement I = D.Invert();
            ECFieldElement L1 = d.Multiply(I).Multiply(dy);
            ECFieldElement L2 = Two(Y1).Multiply(X).Multiply(dx).Multiply(I).Subtract(L1);
            ECFieldElement X4 = (L2.Subtract(L1)).Multiply(L1.Add(L2)).Add(X2);
            ECFieldElement Y4 = (X1.Subtract(X4)).Multiply(L2).Subtract(Y1);

            return new FpPoint(Curve, X4, Y4, IsCompressed);
        }

        public override ECPoint ThreeTimes()
        {
            if (IsInfinity || this.Y.IsZero)
            {
                return this;
            }

            ECFieldElement X1 = this.X, Y1 = this.Y;

            ECFieldElement _2Y1 = Two(Y1);
            ECFieldElement X = _2Y1.Square();
            ECFieldElement Z = Three(X1.Square()).Add(Curve.A);
            ECFieldElement Y = Z.Square();

            ECFieldElement d = Three(X1).Multiply(X).Subtract(Y);
            if (d.IsZero)
            {
                return Curve.Infinity;
            }

            ECFieldElement D = d.Multiply(_2Y1);
            ECFieldElement I = D.Invert();
            ECFieldElement L1 = d.Multiply(I).Multiply(Z);
            ECFieldElement L2 = X.Square().Multiply(I).Subtract(L1);

            ECFieldElement X4 = (L2.Subtract(L1)).Multiply(L1.Add(L2)).Add(X1);
            ECFieldElement Y4 = (X1.Subtract(X4)).Multiply(L2).Subtract(Y1);
            return new FpPoint(Curve, X4, Y4, IsCompressed);
        }

        protected virtual ECFieldElement Two(ECFieldElement x)
        {
            return x.Add(x);
        }

        protected virtual ECFieldElement Three(ECFieldElement x)
        {
            return Two(x).Add(x);
        }

        protected virtual ECFieldElement Four(ECFieldElement x)
        {
            return Two(Two(x));
        }

        protected virtual ECFieldElement Eight(ECFieldElement x)
        {
            return Four(Two(x));
        }

        protected virtual ECFieldElement DoubleProductFromSquares(ECFieldElement a, ECFieldElement b,
            ECFieldElement aSquared, ECFieldElement bSquared)
        {
            /*
             * NOTE: If squaring in the field is faster than multiplication, then this is a quicker
             * way to calculate 2.A.B, if A^2 and B^2 are already known.
             */
            return a.Add(b).Square().Subtract(aSquared).Subtract(bSquared);
        }

        // D.3.2 pg 102 (see Note:)
        public override ECPoint Subtract(
            ECPoint b)
        {
            if (b.IsInfinity)
                return this;

            // Add -b
            return Add(b.Negate());
        }

        public override ECPoint Negate()
        {
            if (IsInfinity)
            {
                return this;
            }

            ECCurve curve = this.Curve;
            //int coord = curve.CoordinateSystem;

            //if (ECCurve.COORD_AFFINE != coord)
            //{
            //    return new FpPoint(curve, X, Y.Negate(), this.m_zs, IsCompressed);
            //}

            return new FpPoint(curve, X, Y.Negate(), IsCompressed);
        }
    }

    /**
     * Elliptic curve points over F2m
     */
    public class F2mPoint
        : ECPointBase
    {
        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         */
        public F2mPoint(
            ECCurve			curve,
            ECFieldElement	x,
            ECFieldElement	y)
            :  this(curve, x, y, false)
        {
        }

        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         * @param withCompression true if encode with point compression.
         */
        public F2mPoint(
            ECCurve			curve,
            ECFieldElement	x,
            ECFieldElement	y,
            bool			withCompression)
            : base(curve, x, y, withCompression)
        {
            if ((x != null && y == null) || (x == null && y != null))
            {
                throw new ArgumentException("Exactly one of the field elements is null");
            }

            if (x != null)
            {
                // Check if x and y are elements of the same field
                F2mFieldElement.CheckFieldElements(x, y);

                // Check if x and a are elements of the same field
                F2mFieldElement.CheckFieldElements(x, curve.A);
            }
        }

        /**
         * Constructor for point at infinity
         */
        [Obsolete("Use ECCurve.Infinity property")]
        public F2mPoint(
            ECCurve curve)
            : this(curve, null, null)
        {
        }

        protected internal override bool CompressionYTilde
        {
            get
            {
                // X9.62 4.2.2 and 4.3.6:
                // if x = 0 then ypTilde := 0, else ypTilde is the rightmost
                // bit of y * x^(-1)
                return !this.X.IsZero && this.Y.Divide(this.X).TestBitZero();
            }
        }

        /**
         * Check, if two <code>ECPoint</code>s can be added or subtracted.
         * @param a The first <code>ECPoint</code> to check.
         * @param b The second <code>ECPoint</code> to check.
         * @throws IllegalArgumentException if <code>a</code> and <code>b</code>
         * cannot be added.
         */
        private static void CheckPoints(
            ECPoint	a,
            ECPoint	b)
        {
            // Check, if points are on the same curve
            if (!a.Curve.Equals(b.Curve))
                throw new ArgumentException("Only points on the same curve can be added or subtracted");

//			F2mFieldElement.CheckFieldElements(a.x, b.x);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#add(org.bouncycastle.math.ec.ECPoint)
         */
        public override ECPoint Add(ECPoint b)
        {
            CheckPoints(this, b);
            return AddSimple((F2mPoint) b);
        }

        /**
         * Adds another <code>ECPoints.F2m</code> to <code>this</code> without
         * checking if both points are on the same curve. Used by multiplication
         * algorithms, because there all points are a multiple of the same point
         * and hence the checks can be omitted.
         * @param b The other <code>ECPoints.F2m</code> to add to
         * <code>this</code>.
         * @return <code>this + b</code>
         */
        internal F2mPoint AddSimple(F2mPoint b)
        {
            if (this.IsInfinity)
                return b;

            if (b.IsInfinity)
                return this;

            F2mFieldElement x2 = (F2mFieldElement) b.X;
            F2mFieldElement y2 = (F2mFieldElement) b.Y;

            // Check if b == this or b == -this
            if (this.X.Equals(x2))
            {
                // this == b, i.e. this must be doubled
                if (this.Y.Equals(y2))
                    return (F2mPoint) this.Twice();

                // this = -other, i.e. the result is the point at infinity
                return (F2mPoint) Curve.Infinity;
            }

            ECFieldElement xSum = this.X.Add(x2);

            F2mFieldElement lambda
                = (F2mFieldElement)(this.Y.Add(y2)).Divide(xSum);

            F2mFieldElement x3
                = (F2mFieldElement)lambda.Square().Add(lambda).Add(xSum).Add(Curve.A);

            F2mFieldElement y3
                = (F2mFieldElement)lambda.Multiply(this.X.Add(x3)).Add(x3).Add(this.Y);

            return new F2mPoint(Curve, x3, y3, IsCompressed);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#subtract(org.bouncycastle.math.ec.ECPoint)
         */
        public override ECPoint Subtract(
            ECPoint b)
        {
            CheckPoints(this, b);
            return SubtractSimple((F2mPoint) b);
        }

        /**
         * Subtracts another <code>ECPoints.F2m</code> from <code>this</code>
         * without checking if both points are on the same curve. Used by
         * multiplication algorithms, because there all points are a multiple
         * of the same point and hence the checks can be omitted.
         * @param b The other <code>ECPoints.F2m</code> to subtract from
         * <code>this</code>.
         * @return <code>this - b</code>
         */
        internal F2mPoint SubtractSimple(
            F2mPoint b)
        {
            if (b.IsInfinity)
                return this;

            // Add -b
            return AddSimple((F2mPoint) b.Negate());
        }

        /* (non-Javadoc)
         * @see Org.BouncyCastle.Math.EC.ECPoint#twice()
         */
        public override ECPoint Twice()
        {
            // Twice identity element (point at infinity) is identity
            if (this.IsInfinity)
                return this;

            // if x1 == 0, then (x1, y1) == (x1, x1 + y1)
            // and hence this = -this and thus 2(x1, y1) == infinity
            if (this.X.IsZero)
            {
                return Curve.Infinity;
            }

            F2mFieldElement lambda = (F2mFieldElement) this.X.Add(this.Y.Divide(this.X));
            F2mFieldElement x2 = (F2mFieldElement)lambda.Square().Add(lambda).Add(Curve.A);
            ECFieldElement ONE = Curve.FromBigInteger(BigInteger.One);
            F2mFieldElement y2 = (F2mFieldElement)this.X.Square().Add(
                x2.Multiply(lambda.Add(ONE)));

            return new F2mPoint(Curve, x2, y2, IsCompressed);
        }

        public override ECPoint Negate()
        {
            if (IsInfinity)
            {
                return this;
            }

            ECFieldElement X1 = this.X;
            if (X1.IsZero)
            {
                return this;
            }

            return new F2mPoint(Curve, X1, X1.Add(this.Y), IsCompressed);
        }
    }
}
