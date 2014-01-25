using System;
using System.Collections;
using System.Diagnostics;
using System.Text;

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

        protected ECPoint(ECCurve curve, ECFieldElement	x, ECFieldElement y, bool withCompression)
            : this(curve, x, y, GetInitialZCoords(curve), withCompression)
        {
        }

        internal ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
        {
            this.m_curve = curve;
            this.m_x = x;
            this.m_y = y;
            this.m_zs = zs;
            this.m_withCompression = withCompression;
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

        /**
         * Normalizes this point, and then returns the affine x-coordinate.
         * 
         * Note: normalization can be expensive, this method is deprecated in favour
         * of caller-controlled normalization.
         */
        [Obsolete("Use AffineXCoord, or Normalize() and XCoord, instead")]
        public virtual ECFieldElement X
        {
            get { return Normalize().XCoord; }
        }

        /**
         * Normalizes this point, and then returns the affine y-coordinate.
         * 
         * Note: normalization can be expensive, this method is deprecated in favour
         * of caller-controlled normalization.
         */
        [Obsolete("Use AffineYCoord, or Normalize() and YCoord, instead")]
        public virtual ECFieldElement Y
        {
            get { return Normalize().YCoord; }
        }

        /**
         * Returns the affine x-coordinate after checking that this point is normalized.
         * 
         * @return The affine x-coordinate of this point
         * @throws IllegalStateException if the point is not normalized
         */
        public virtual ECFieldElement AffineXCoord
        {
            get
            {
                CheckNormalized();
                return XCoord;
            }
        }

        /**
         * Returns the affine y-coordinate after checking that this point is normalized
         * 
         * @return The affine y-coordinate of this point
         * @throws IllegalStateException if the point is not normalized
         */
        public virtual ECFieldElement AffineYCoord
        {
            get
            {
                CheckNormalized();
                return YCoord;
            }
        }

        /**
         * Returns the x-coordinate.
         * 
         * Caution: depending on the curve's coordinate system, this may not be the same value as in an
         * affine coordinate system; use Normalize() to get a point where the coordinates have their
         * affine values, or use AffineXCoord if you expect the point to already have been normalized.
         * 
         * @return the x-coordinate of this point
         */
        public virtual ECFieldElement XCoord
        {
            get { return m_x; }
        }

        /**
         * Returns the y-coordinate.
         * 
         * Caution: depending on the curve's coordinate system, this may not be the same value as in an
         * affine coordinate system; use Normalize() to get a point where the coordinates have their
         * affine values, or use AffineYCoord if you expect the point to already have been normalized.
         * 
         * @return the y-coordinate of this point
         */
        public virtual ECFieldElement YCoord
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

        protected internal ECFieldElement RawXCoord
        {
            get { return m_x; }
        }

        protected internal ECFieldElement RawYCoord
        {
            get { return m_y; }
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
                || IsInfinity
                || GetZCoord(0).IsOne;
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
            switch (this.CurveCoordinateSystem)
            {
                case ECCurve.COORD_HOMOGENEOUS:
                case ECCurve.COORD_LAMBDA_PROJECTIVE:
                {
                    return CreateScaledPoint(zInv, zInv);
                }
                case ECCurve.COORD_JACOBIAN:
                case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
                case ECCurve.COORD_JACOBIAN_MODIFIED:
                {
                    ECFieldElement zInv2 = zInv.Square(), zInv3 = zInv2.Multiply(zInv);
                    return CreateScaledPoint(zInv2, zInv3);
                }
                default:
                {
                    throw new InvalidOperationException("not a projective coordinate system");
                }
            }
        }

        protected virtual ECPoint CreateScaledPoint(ECFieldElement sx, ECFieldElement sy)
        {
            return Curve.CreateRawPoint(RawXCoord.Multiply(sx), RawYCoord.Multiply(sy), IsCompressed);
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

            ECCurve c1 = this.Curve, c2 = other.Curve;
            bool n1 = (null == c1), n2 = (null == c2);
            bool i1 = IsInfinity, i2 = other.IsInfinity;

            if (i1 || i2)
            {
                return (i1 && i2) && (n1 || n2 || c1.Equals(c2));
            }

            ECPoint p1 = this, p2 = other;
            if (n1 && n2)
            {
                // Points with null curve are in affine form, so already normalized
            }
            else if (n1)
            {
                p2 = p2.Normalize();
            }
            else if (n2)
            {
                p1 = p1.Normalize();
            }
            else if (!c1.Equals(c2))
            {
                return false;
            }
            else
            {
                // TODO Consider just requiring already normalized, to avoid silent performance degradation

                ECPoint[] points = new ECPoint[] { this, c1.ImportPoint(p2) };

                // TODO This is a little strong, really only requires coZNormalizeAll to get Zs equal
                c1.NormalizeAll(points);

                p1 = points[0];
                p2 = points[1];
            }

            return p1.XCoord.Equals(p2.XCoord) && p1.YCoord.Equals(p2.YCoord);
        }

        public override int GetHashCode()
        {
            ECCurve c = this.Curve;
            int hc = (null == c) ? 0 : ~c.GetHashCode();

            if (!this.IsInfinity)
            {
                // TODO Consider just requiring already normalized, to avoid silent performance degradation

                ECPoint p = Normalize();

                hc ^= p.XCoord.GetHashCode() * 17;
                hc ^= p.YCoord.GetHashCode() * 257;
            }

            return hc;
        }

        public override string ToString()
        {
            if (this.IsInfinity)
            {
                return "INF";
            }

            StringBuilder sb = new StringBuilder();
            sb.Append('(');
            sb.Append(RawXCoord);
            sb.Append(',');
            sb.Append(RawYCoord);
            for (int i = 0; i < m_zs.Length; ++i)
            {
                sb.Append(',');
                sb.Append(m_zs[i]);
            }
            sb.Append(')');
            return sb.ToString();
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

        protected internal ECPointBase(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
            : base(curve, x, y, zs, withCompression)
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

            byte[] X = normed.XCoord.GetEncoded();

            if (compressed)
            {
                byte[] PO = new byte[X.Length + 1];
                PO[0] = (byte)(normed.CompressionYTilde ? 0x03 : 0x02);
                Array.Copy(X, 0, PO, 1, X.Length);
                return PO;
            }

            byte[] Y = normed.YCoord.GetEncoded();

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

        internal FpPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
            : base(curve, x, y, zs, withCompression)
        {
        }

        protected internal override bool CompressionYTilde
        {
            get { return this.AffineYCoord.TestBitZero(); }
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

            ECCurve curve = this.Curve;
            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = this.RawXCoord, Y1 = this.RawYCoord;
            ECFieldElement X2 = b.RawXCoord, Y2 = b.RawYCoord;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                {
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

                case ECCurve.COORD_HOMOGENEOUS:
                {
                    ECFieldElement Z1 = this.GetZCoord(0);
                    ECFieldElement Z2 = b.GetZCoord(0);

                    bool Z1IsOne = Z1.IsOne;
                    bool Z2IsOne = Z2.IsOne;

                    ECFieldElement u1 = Z1IsOne ? Y2 : Y2.Multiply(Z1);
                    ECFieldElement u2 = Z2IsOne ? Y1 : Y1.Multiply(Z2);
                    ECFieldElement u = u1.Subtract(u2);
                    ECFieldElement v1 = Z1IsOne ? X2 : X2.Multiply(Z1);
                    ECFieldElement v2 = Z2IsOne ? X1 : X1.Multiply(Z2);
                    ECFieldElement v = v1.Subtract(v2);

                    // Check if b == this or b == -this
                    if (v.IsZero)
                    {
                        if (u.IsZero)
                        {
                            // this == b, i.e. this must be doubled
                            return this.Twice();
                        }

                        // this == -b, i.e. the result is the point at infinity
                        return curve.Infinity;
                    }

                    // TODO Optimize for when w == 1
                    ECFieldElement w = Z1IsOne ? Z2 : Z2IsOne ? Z1 : Z1.Multiply(Z2);
                    ECFieldElement vSquared = v.Square();
                    ECFieldElement vCubed = vSquared.Multiply(v);
                    ECFieldElement vSquaredV2 = vSquared.Multiply(v2);
                    ECFieldElement A = u.Square().Multiply(w).Subtract(vCubed).Subtract(Two(vSquaredV2));

                    ECFieldElement X3 = v.Multiply(A);
                    ECFieldElement Y3 = vSquaredV2.Subtract(A).Multiply(u).Subtract(vCubed.Multiply(u2));
                    ECFieldElement Z3 = vCubed.Multiply(w);

                    return new FpPoint(curve, X3, Y3, new ECFieldElement[] { Z3 }, IsCompressed);
                }

                default:
                {
                    throw new InvalidOperationException("unsupported coordinate system");
                }
            }
        }

        // B.3 pg 62
        public override ECPoint Twice()
        {
            if (this.IsInfinity)
            {
                return this;
            }

            ECCurve curve = this.Curve;

            ECFieldElement Y1 = this.RawYCoord;
            if (Y1.IsZero) 
            {
                return curve.Infinity;
            }

            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = this.RawXCoord;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                {
                    ECFieldElement X1Squared = X1.Square();
                    ECFieldElement gamma = Three(X1Squared).Add(this.Curve.A).Divide(Two(Y1));
                    ECFieldElement X3 = gamma.Square().Subtract(Two(X1));
                    ECFieldElement Y3 = gamma.Multiply(X1.Subtract(X3)).Subtract(Y1);

                    return new FpPoint(Curve, X3, Y3, IsCompressed);
                }

                case ECCurve.COORD_HOMOGENEOUS:
                {
                    ECFieldElement Z1 = this.GetZCoord(0);

                    bool Z1IsOne = Z1.IsOne;

                    // TODO Optimize for small negative a4 and -3
                    ECFieldElement w = curve.A;
                    if (!w.IsZero && !Z1IsOne)
                    {
                        w = w.Multiply(Z1.Square());
                    }
                    w = w.Add(Three(X1.Square()));

                    ECFieldElement s = Z1IsOne ? Y1 : Y1.Multiply(Z1);
                    ECFieldElement t = Z1IsOne ? Y1.Square() : s.Multiply(Y1);
                    ECFieldElement B = X1.Multiply(t);
                    ECFieldElement _4B = Four(B);
                    ECFieldElement h = w.Square().Subtract(Two(_4B));

                    ECFieldElement _2s = Two(s);
                    ECFieldElement X3 = h.Multiply(_2s);
                    ECFieldElement _2t = Two(t);
                    ECFieldElement Y3 = _4B.Subtract(h).Multiply(w).Subtract(Two(_2t.Square()));
                    ECFieldElement _4sSquared = Z1IsOne ? Two(_2t) : _2s.Square();
                    ECFieldElement Z3 = Two(_4sSquared).Multiply(s);

                    return new FpPoint(curve, X3, Y3, new ECFieldElement[] { Z3 }, IsCompressed);
                }

                default:
                {
                    throw new InvalidOperationException("unsupported coordinate system");
                }
            }
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

            ECFieldElement Y1 = this.RawYCoord;
            if (Y1.IsZero)
            {
                return b;
            }

            ECCurve curve = this.Curve;
            int coord = curve.CoordinateSystem;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                {
                    ECFieldElement X1 = this.RawXCoord;
                    ECFieldElement X2 = b.RawXCoord, Y2 = b.RawYCoord;

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
                default:
                {
                    return Twice().Add(b);
                }
            }
        }

        public override ECPoint ThreeTimes()
        {
            if (IsInfinity)
                return this;

            ECFieldElement Y1 = this.RawYCoord;
            if (Y1.IsZero)
                return this;

            ECCurve curve = this.Curve;
            int coord = curve.CoordinateSystem;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                {
                    ECFieldElement X1 = this.RawXCoord;

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
                default:
                {
                    // NOTE: Be careful about recursions between twicePlus and threeTimes
                    return Twice().Add(this);
                }
            }
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
            int coord = curve.CoordinateSystem;

            if (ECCurve.COORD_AFFINE != coord)
            {
                return new FpPoint(curve, XCoord, YCoord.Negate(), this.m_zs, IsCompressed);
            }

            return new FpPoint(curve, XCoord, YCoord.Negate(), IsCompressed);
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
                if (curve != null)
                {
                    F2mFieldElement.CheckFieldElements(x, curve.A);
                }
            }
        }

        internal F2mPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
            : base(curve, x, y, zs, withCompression)
        {
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

        public override ECFieldElement YCoord
        {
            get
            {
                int coord = this.CurveCoordinateSystem;

                switch (coord)
                {
                    case ECCurve.COORD_LAMBDA_AFFINE:
                    case ECCurve.COORD_LAMBDA_PROJECTIVE:
                    {
                        ECFieldElement X = RawXCoord, L = RawYCoord;

                        // TODO The X == 0 stuff needs further thought
                        if (this.IsInfinity || X.IsZero)
                            return L;

                        // Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
                        ECFieldElement Y = L.Subtract(X).Multiply(X);
                        if (ECCurve.COORD_LAMBDA_PROJECTIVE == coord)
                        {
                            ECFieldElement Z = GetZCoord(0);
                            if (!Z.IsOne)
                            {
                                Y = Y.Divide(Z);
                            }
                        }
                        return Y;
                    }
                    default:
                    {
                        return RawYCoord;
                    }
                }
            }
        }

        protected internal override bool CompressionYTilde
        {
            get
            {
                ECFieldElement X = this.RawXCoord;
                if (X.IsZero)
                {
                    return false;
                }

                ECFieldElement Y = this.RawYCoord;

                switch (this.CurveCoordinateSystem)
                {
                    case ECCurve.COORD_LAMBDA_AFFINE:
                    case ECCurve.COORD_LAMBDA_PROJECTIVE:
                    {
                        // Y is actually Lambda (X + Y/X) here
                        return Y.Subtract(X).TestBitZero();
                    }
                    default:
                    {
                        return Y.Divide(X).TestBitZero();
                    }
                }

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

            ECCurve curve = this.Curve;
            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = this.RawXCoord;
            ECFieldElement X2 = b.RawXCoord;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                {
                    ECFieldElement Y1 = this.RawYCoord;
                    ECFieldElement Y2 = b.RawYCoord;

                    if (X1.Equals(X2))
                    {
                        if (Y1.Equals(Y2))
                        {
                            return (F2mPoint)Twice();
                        }

                        return (F2mPoint)curve.Infinity;
                    }

                    ECFieldElement sumX = X1.Add(X2);
                    ECFieldElement L = Y1.Add(Y2).Divide(sumX);

                    ECFieldElement X3 = L.Square().Add(L).Add(sumX).Add(curve.A);
                    ECFieldElement Y3 = L.Multiply(X1.Add(X3)).Add(X3).Add(Y1);

                    return new F2mPoint(curve, X3, Y3, IsCompressed);
                }
                case ECCurve.COORD_HOMOGENEOUS:
                {
                    ECFieldElement Y1 = this.RawYCoord, Z1 = this.GetZCoord(0);
                    ECFieldElement Y2 = b.RawYCoord, Z2 = b.GetZCoord(0);

                    bool Z2IsOne = Z2.IsOne;

                    ECFieldElement U1 = Z1.Multiply(Y2);
                    ECFieldElement U2 = Z2IsOne ? Y1 : Y1.Multiply(Z2);
                    ECFieldElement U = U1.Subtract(U2);
                    ECFieldElement V1 = Z1.Multiply(X2);
                    ECFieldElement V2 = Z2IsOne ? X1 : X1.Multiply(Z2);
                    ECFieldElement V = V1.Subtract(V2);

                    if (V1.Equals(V2))
                    {
                        if (U1.Equals(U2))
                        {
                            return (F2mPoint)Twice();
                        }

                        return (F2mPoint)curve.Infinity;
                    }

                    ECFieldElement VSq = V.Square();
                    ECFieldElement W = Z2IsOne ? Z1 : Z1.Multiply(Z2);
                    ECFieldElement A = U.Square().Add(U.Multiply(V).Add(VSq.Multiply(curve.A))).Multiply(W).Add(V.Multiply(VSq));

                    ECFieldElement X3 = V.Multiply(A);
                    ECFieldElement VSqZ2 = Z2IsOne ? VSq : VSq.Multiply(Z2);
                    ECFieldElement Y3 = VSqZ2.Multiply(U.Multiply(X1).Add(Y1.Multiply(V))).Add(A.Multiply(U.Add(V)));
                    ECFieldElement Z3 = VSq.Multiply(V).Multiply(W);

                    return new F2mPoint(curve, X3, Y3, new ECFieldElement[] { Z3 }, IsCompressed);
                }
                case ECCurve.COORD_LAMBDA_PROJECTIVE:
                {
                    if (X1.IsZero)
                        return b.AddSimple(this);

                    ECFieldElement L1 = this.RawYCoord, Z1 = this.GetZCoord(0);
                    ECFieldElement L2 = b.RawYCoord, Z2 = b.GetZCoord(0);

                    bool Z1IsOne = Z1.IsOne;
                    ECFieldElement U2 = X2, S2 = L2;
                    if (!Z1IsOne)
                    {
                        U2 = U2.Multiply(Z1);
                        S2 = S2.Multiply(Z1);
                    }

                    bool Z2IsOne = Z2.IsOne;
                    ECFieldElement U1 = X1, S1 = L1;
                    if (!Z2IsOne)
                    {
                        U1 = U1.Multiply(Z2);
                        S1 = S1.Multiply(Z2);
                    }

                    ECFieldElement A = S1.Add(S2);
                    ECFieldElement B = U1.Add(U2);

                    if (B.IsZero)
                    {
                        if (A.IsZero)
                        {
                            return (F2mPoint)Twice();
                        }

                        return (F2mPoint)curve.Infinity;
                    }

                    ECFieldElement X3, L3, Z3;
                    if (X2.IsZero)
                    {
                        // TODO This can probably be optimized quite a bit

                        ECFieldElement Y1 = this.RawYCoord, Y2 = L2;
                        ECFieldElement L = Y1.Add(Y2).Divide(X1);

                        X3 = L.Square().Add(L).Add(X1).Add(curve.A);
                        ECFieldElement Y3 = L.Multiply(X1.Add(X3)).Add(X3).Add(Y1);
                        L3 = X3.IsZero ? Y3 : Y3.Divide(X3).Add(X3);
                        Z3 = curve.FromBigInteger(BigInteger.One);
                    }
                    else
                    {
                        B = B.Square();

                        ECFieldElement AU1 = A.Multiply(U1);
                        ECFieldElement AU2 = A.Multiply(U2);
                        ECFieldElement ABZ2 = A.Multiply(B);
                        if (!Z2IsOne)
                        {
                            ABZ2 = ABZ2.Multiply(Z2);
                        }

                        X3 = AU1.Multiply(AU2);
                        L3 = AU2.Add(B).Square().Add(ABZ2.Multiply(L1.Add(Z1)));

                        Z3 = ABZ2;
                        if (!Z1IsOne)
                        {
                            Z3 = Z3.Multiply(Z1);
                        }
                    }

                    return new F2mPoint(curve, X3, L3, new ECFieldElement[] { Z3 }, IsCompressed);
                }
                default:
                {
                    throw new InvalidOperationException("unsupported coordinate system");
                }
            }
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

        public virtual F2mPoint Tau()
        {
            if (this.IsInfinity)
            {
                return this;
            }

            ECCurve curve = this.Curve;
            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = this.RawXCoord;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                case ECCurve.COORD_LAMBDA_AFFINE:
                {
                    ECFieldElement Y1 = this.RawYCoord;
                    return new F2mPoint(curve, X1.Square(), Y1.Square(), IsCompressed);
                }
                case ECCurve.COORD_HOMOGENEOUS:
                case ECCurve.COORD_LAMBDA_PROJECTIVE:
                {
                    ECFieldElement Y1 = this.RawYCoord, Z1 = this.GetZCoord(0);
                    return new F2mPoint(curve, X1.Square(), Y1.Square(), new ECFieldElement[] { Z1.Square() }, IsCompressed);
                }
                default:
                {
                    throw new InvalidOperationException("unsupported coordinate system");
                }
            }
        }

        /* (non-Javadoc)
         * @see Org.BouncyCastle.Math.EC.ECPoint#twice()
         */
        public override ECPoint Twice()
        {
            if (this.IsInfinity)
                return this;

            ECCurve curve = this.Curve;

            ECFieldElement X1 = this.RawXCoord;
            if (X1.IsZero)
            {
                // A point with X == 0 is it's own additive inverse
                return curve.Infinity;
            }

            int coord = curve.CoordinateSystem;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                {
                    ECFieldElement Y1 = this.RawYCoord;

                    ECFieldElement L1 = Y1.Divide(X1).Add(X1);

                    ECFieldElement X3 = L1.Square().Add(L1).Add(curve.A);
                    ECFieldElement Y3 = X1.Square().Add(X3.Multiply(L1.AddOne()));

                    return new F2mPoint(curve, X3, Y3, IsCompressed);
                }
                case ECCurve.COORD_HOMOGENEOUS:
                {
                    ECFieldElement Y1 = this.RawYCoord, Z1 = this.GetZCoord(0);

                    bool Z1IsOne = Z1.IsOne;
                    ECFieldElement X1Z1 = Z1IsOne ? X1 : X1.Multiply(Z1);
                    ECFieldElement Y1Z1 = Z1IsOne ? Y1 : Y1.Multiply(Z1);

                    ECFieldElement X1Sq = X1.Square();
                    ECFieldElement S = X1Sq.Add(Y1Z1);
                    ECFieldElement V = X1Z1;
                    ECFieldElement vSquared = V.Square();
                    ECFieldElement h = S.Square().Add(S.Multiply(V)).Add(curve.A.Multiply(vSquared));

                    ECFieldElement X3 = V.Multiply(h);
                    ECFieldElement Y3 = h.Multiply(S.Add(V)).Add(X1Sq.Square().Multiply(V));
                    ECFieldElement Z3 = V.Multiply(vSquared);

                    return new F2mPoint(curve, X3, Y3, new ECFieldElement[] { Z3 }, IsCompressed);
                }
                case ECCurve.COORD_LAMBDA_PROJECTIVE:
                {
                    ECFieldElement L1 = this.RawYCoord, Z1 = this.GetZCoord(0);

                    bool Z1IsOne = Z1.IsOne;
                    ECFieldElement L1Z1 = Z1IsOne ? L1 : L1.Multiply(Z1);
                    ECFieldElement Z1Sq = Z1IsOne ? Z1 : Z1.Square();
                    ECFieldElement a = curve.A;
                    ECFieldElement aZ1Sq = Z1IsOne ? a : a.Multiply(Z1Sq);
                    ECFieldElement T = L1.Square().Add(L1Z1).Add(aZ1Sq);

                    ECFieldElement X3 = T.Square();
                    ECFieldElement Z3 = Z1IsOne ? T : T.Multiply(Z1Sq);

                    ECFieldElement b = curve.B;
                    ECFieldElement L3;
                    if (b.BitLength < (curve.FieldSize >> 1))
                    {
                        ECFieldElement t1 = L1.Add(X1).Square();
                        ECFieldElement t4;
                        if (b.IsOne)
                        {
                            t4 = aZ1Sq.Add(Z1Sq).Square();
                        }
                        else
                        {
                            // TODO t2/t3 can be calculated with one square if we pre-compute sqrt(b)
                            ECFieldElement t2 = aZ1Sq.Square();
                            ECFieldElement t3 = b.Multiply(Z1Sq.Square());
                            t4 = t2.Add(t3);
                        }
                        L3 = t1.Add(T).Add(Z1Sq).Multiply(t1).Add(t4).Add(X3);
                        if (a.IsZero)
                        {
                            L3 = L3.Add(Z3);
                        }
                        else if (!a.IsOne)
                        {
                            L3 = L3.Add(a.AddOne().Multiply(Z3));
                        }
                    }
                    else
                    {
                        ECFieldElement X1Z1 = Z1IsOne ? X1 : X1.Multiply(Z1);
                        L3 = X1Z1.Square().Add(X3).Add(T.Multiply(L1Z1)).Add(Z3);
                    }

                    return new F2mPoint(curve, X3, L3, new ECFieldElement[] { Z3 }, IsCompressed);
                }
                default:
                {
                    throw new InvalidOperationException("unsupported coordinate system");
                }
            }
        }

        public override ECPoint TwicePlus(ECPoint b)
        {
            if (this.IsInfinity)
                return b;
            if (b.IsInfinity)
                return Twice();

            ECCurve curve = this.Curve;

            ECFieldElement X1 = this.RawXCoord;
            if (X1.IsZero)
            {
                // A point with X == 0 is it's own additive inverse
                return b;
            }

            int coord = curve.CoordinateSystem;

            switch (coord)
            {
                case ECCurve.COORD_LAMBDA_PROJECTIVE:
                {
                    // NOTE: twicePlus() only optimized for lambda-affine argument
                    ECFieldElement X2 = b.RawXCoord, Z2 = b.GetZCoord(0);
                    if (X2.IsZero || !Z2.IsOne)
                    {
                        return Twice().Add(b);
                    }

                    ECFieldElement L1 = this.RawYCoord, Z1 = this.GetZCoord(0);
                    ECFieldElement L2 = b.RawYCoord;

                    ECFieldElement X1Sq = X1.Square();
                    ECFieldElement L1Sq = L1.Square();
                    ECFieldElement Z1Sq = Z1.Square();
                    ECFieldElement L1Z1 = L1.Multiply(Z1);

                    ECFieldElement T = curve.A.Multiply(Z1Sq).Add(L1Sq).Add(L1Z1);
                    ECFieldElement L2plus1 = L2.AddOne();
                    ECFieldElement A = curve.A.Add(L2plus1).Multiply(Z1Sq).Add(L1Sq).Multiply(T).Add(X1Sq.Multiply(Z1Sq));
                    ECFieldElement X2Z1Sq = X2.Multiply(Z1Sq);
                    ECFieldElement B = X2Z1Sq.Add(T).Square();

                    ECFieldElement X3 = A.Square().Multiply(X2Z1Sq);
                    ECFieldElement Z3 = A.Multiply(B).Multiply(Z1Sq);
                    ECFieldElement L3 = A.Add(B).Square().Multiply(T).Add(L2plus1.Multiply(Z3));

                    return new F2mPoint(curve, X3, L3, new ECFieldElement[] { Z3 }, IsCompressed);
                }
                default:
                {
                    return Twice().Add(b);
                }
            }
        }

        public override ECPoint Negate()
        {
            if (this.IsInfinity)
                return this;

            ECFieldElement X = this.RawXCoord;
            if (X.IsZero)
                return this;

            ECCurve curve = this.Curve;
            int coord = curve.CoordinateSystem;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                {
                    ECFieldElement Y = this.RawYCoord;
                    return new F2mPoint(curve, X, Y.Add(X), IsCompressed);
                }
                case ECCurve.COORD_HOMOGENEOUS:
                {
                    ECFieldElement Y = this.RawYCoord, Z = this.GetZCoord(0);
                    return new F2mPoint(curve, X, Y.Add(X), new ECFieldElement[] { Z }, IsCompressed);
                }
                case ECCurve.COORD_LAMBDA_AFFINE:
                {
                    ECFieldElement L = this.RawYCoord;
                    return new F2mPoint(curve, X, L.AddOne(), IsCompressed);
                }
                case ECCurve.COORD_LAMBDA_PROJECTIVE:
                {
                    // L is actually Lambda (X + Y/X) here
                    ECFieldElement L = this.RawYCoord, Z = this.GetZCoord(0);
                    return new F2mPoint(curve, X, L.Add(Z), new ECFieldElement[] { Z }, IsCompressed);
                }
                default:
                {
                    throw new InvalidOperationException("unsupported coordinate system");
                }
            }
        }
    }
}
