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

        protected virtual ECFieldElement RawXCoord
        {
            get { return m_x; }
        }

        protected virtual ECFieldElement RawYCoord
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

            ECFieldElement X1 = this.XCoord, Y1 = this.YCoord;
            ECFieldElement X2 = b.XCoord, Y2 = b.YCoord;

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

            ECFieldElement Y1 = this.YCoord;
            if (Y1.IsZero) 
            {
                return curve.Infinity;
            }

            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = this.XCoord;

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

            ECFieldElement Y1 = this.YCoord;
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
                    ECFieldElement X1 = this.XCoord;
                    ECFieldElement X2 = b.XCoord, Y2 = b.YCoord;

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
            if (IsInfinity || this.YCoord.IsZero)
            {
                return this;
            }

            ECCurve curve = this.Curve;
            int coord = curve.CoordinateSystem;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                {
                    ECFieldElement X1 = this.XCoord, Y1 = this.YCoord;

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

            F2mFieldElement x2 = (F2mFieldElement) b.XCoord;
            F2mFieldElement y2 = (F2mFieldElement) b.YCoord;

            // Check if b == this or b == -this
            if (this.XCoord.Equals(x2))
            {
                // this == b, i.e. this must be doubled
                if (this.YCoord.Equals(y2))
                    return (F2mPoint) this.Twice();

                // this = -other, i.e. the result is the point at infinity
                return (F2mPoint) Curve.Infinity;
            }

            ECFieldElement xSum = this.XCoord.Add(x2);

            F2mFieldElement lambda
                = (F2mFieldElement)(this.YCoord.Add(y2)).Divide(xSum);

            F2mFieldElement x3
                = (F2mFieldElement)lambda.Square().Add(lambda).Add(xSum).Add(Curve.A);

            F2mFieldElement y3
                = (F2mFieldElement)lambda.Multiply(this.XCoord.Add(x3)).Add(x3).Add(this.YCoord);

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

        public virtual F2mPoint Tau()
        {
            if (this.IsInfinity)
            {
                return this;
            }

            ECCurve curve = this.Curve;
            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = this.XCoord;

            switch (coord)
            {
                case ECCurve.COORD_AFFINE:
                case ECCurve.COORD_LAMBDA_AFFINE:
                {
                    ECFieldElement Y1 = this.YCoord;
                    return new F2mPoint(curve, X1.Square(), Y1.Square(), IsCompressed);
                }
                case ECCurve.COORD_HOMOGENEOUS:
                case ECCurve.COORD_LAMBDA_PROJECTIVE:
                {
                    ECFieldElement Y1 = this.YCoord, Z1 = this.GetZCoord(0);
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
            // Twice identity element (point at infinity) is identity
            if (this.IsInfinity)
                return this;

            // if x1 == 0, then (x1, y1) == (x1, x1 + y1)
            // and hence this = -this and thus 2(x1, y1) == infinity
            if (this.XCoord.IsZero)
            {
                return Curve.Infinity;
            }

            F2mFieldElement lambda = (F2mFieldElement) this.XCoord.Add(this.YCoord.Divide(this.XCoord));
            F2mFieldElement x2 = (F2mFieldElement)lambda.Square().Add(lambda).Add(Curve.A);
            ECFieldElement ONE = Curve.FromBigInteger(BigInteger.One);
            F2mFieldElement y2 = (F2mFieldElement)this.XCoord.Square().Add(
                x2.Multiply(lambda.Add(ONE)));

            return new F2mPoint(Curve, x2, y2, IsCompressed);
        }

        public override ECPoint Negate()
        {
            if (IsInfinity)
            {
                return this;
            }

            ECFieldElement X1 = this.XCoord;
            if (X1.IsZero)
            {
                return this;
            }

            return new F2mPoint(Curve, X1, X1.Add(this.YCoord), IsCompressed);
        }
    }
}
