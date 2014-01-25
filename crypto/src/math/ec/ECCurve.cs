using System;
using System.Collections;

using Org.BouncyCastle.Math.EC.Abc;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Math.Field;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC
{
    /// <remarks>Base class for an elliptic curve.</remarks>
    public abstract class ECCurve
    {
        public const int COORD_AFFINE = 0;
        public const int COORD_HOMOGENEOUS = 1;
        public const int COORD_JACOBIAN = 2;
        public const int COORD_JACOBIAN_CHUDNOVSKY = 3;
        public const int COORD_JACOBIAN_MODIFIED = 4;
        public const int COORD_LAMBDA_AFFINE = 5;
        public const int COORD_LAMBDA_PROJECTIVE = 6;
        public const int COORD_SKEWED = 7;

        public static int[] GetAllCoordinateSystems()
        {
            return new int[]{ COORD_AFFINE, COORD_HOMOGENEOUS, COORD_JACOBIAN, COORD_JACOBIAN_CHUDNOVSKY,
                COORD_JACOBIAN_MODIFIED, COORD_LAMBDA_AFFINE, COORD_LAMBDA_PROJECTIVE, COORD_SKEWED };
        }

        public class Config
        {
            protected ECCurve outer;
            protected int coord;
            protected ECMultiplier multiplier;

            internal Config(ECCurve outer, int coord, ECMultiplier multiplier)
            {
                this.outer = outer;
                this.coord = coord;
                this.multiplier = multiplier;
            }

            public Config SetCoordinateSystem(int coord)
            {
                this.coord = coord;
                return this;
            }

            public Config SetMultiplier(ECMultiplier multiplier)
            {
                this.multiplier = multiplier;
                return this;
            }

            public ECCurve Create()
            {
                if (!outer.SupportsCoordinateSystem(coord))
                {
                    throw new InvalidOperationException("unsupported coordinate system");
                }

                ECCurve c = outer.CloneCurve();
                if (c == outer)
                {
                    throw new InvalidOperationException("implementation returned current curve");
                }

                c.m_coord = coord;
                c.m_multiplier = multiplier;

                return c;
            }
        }

        protected IFiniteField m_field;
        protected ECFieldElement m_a, m_b;

        protected int m_coord = COORD_AFFINE;
        protected ECMultiplier m_multiplier = null;

        protected ECCurve(IFiniteField field)
        {
            this.m_field = field;
        }

        public abstract int FieldSize { get; }
        public abstract ECFieldElement FromBigInteger(BigInteger x);

        public virtual Config Configure()
        {
            return new Config(this, this.m_coord, this.m_multiplier);
        }

        public virtual ECPoint CreatePoint(BigInteger x, BigInteger y)
        {
            return CreatePoint(x, y, false);
        }

        public abstract ECPoint CreatePoint(BigInteger x, BigInteger y, bool withCompression);

        protected abstract ECCurve CloneCurve();

        protected internal abstract ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression);

        protected virtual ECMultiplier CreateDefaultMultiplier()
        {
            return new WNafMultiplier();
        }

        public virtual bool SupportsCoordinateSystem(int coord)
        {
            return coord == COORD_AFFINE;
        }

        public virtual PreCompInfo GetPreCompInfo(ECPoint p)
        {
            CheckPoint(p);
            return p.m_preCompInfo;
        }

        /**
         * Sets the <code>PreCompInfo</code> for a point on this curve. Used by
         * <code>ECMultiplier</code>s to save the precomputation for this <code>ECPoint</code> for use
         * by subsequent multiplication.
         * 
         * @param point
         *            The <code>ECPoint</code> to store precomputations for.
         * @param preCompInfo
         *            The values precomputed by the <code>ECMultiplier</code>.
         */
        public virtual void SetPreCompInfo(ECPoint point, PreCompInfo preCompInfo)
        {
            CheckPoint(point);
            point.m_preCompInfo = preCompInfo;
        }

        public virtual ECPoint ImportPoint(ECPoint p)
        {
            if (this == p.Curve)
            {
                return p;
            }
            if (p.IsInfinity)
            {
                return Infinity;
            }

            // TODO Default behaviour could be improved if the two curves have the same coordinate system by copying any Z coordinates.
            p = p.Normalize();

            return CreatePoint(p.XCoord.ToBigInteger(), p.YCoord.ToBigInteger(), p.IsCompressed);
        }

        /**
         * Normalization ensures that any projective coordinate is 1, and therefore that the x, y
         * coordinates reflect those of the equivalent point in an affine coordinate system. Where more
         * than one point is to be normalized, this method will generally be more efficient than
         * normalizing each point separately.
         * 
         * @param points
         *            An array of points that will be updated in place with their normalized versions,
         *            where necessary
         */
        public virtual void NormalizeAll(ECPoint[] points)
        {
            CheckPoints(points);

            if (this.CoordinateSystem == ECCurve.COORD_AFFINE)
            {
                return;
            }

            /*
             * Figure out which of the points actually need to be normalized
             */
            ECFieldElement[] zs = new ECFieldElement[points.Length];
            int[] indices = new int[points.Length];
            int count = 0;
            for (int i = 0; i < points.Length; ++i)
            {
                ECPoint p = points[i];
                if (null != p && !p.IsNormalized())
                {
                    zs[count] = p.GetZCoord(0);
                    indices[count++] = i;
                }
            }

            if (count == 0)
            {
                return;
            }

            ECAlgorithms.MontgomeryTrick(zs, 0, count);

            for (int j = 0; j < count; ++j)
            {
                int index = indices[j];
                points[index] = points[index].Normalize(zs[j]);
            }
        }

        public abstract ECPoint Infinity { get; }

        public virtual IFiniteField Field
        {
            get { return m_field; }
        }

        public virtual ECFieldElement A
        {
            get { return m_a; }
        }

        public virtual ECFieldElement B
        {
            get { return m_b; }
        }

        public virtual int CoordinateSystem
        {
            get { return m_coord; }
        }

        protected virtual void CheckPoint(ECPoint point)
        {
            if (null == point || (this != point.Curve))
                throw new ArgumentException("must be non-null and on this curve", "point");
        }

        protected virtual void CheckPoints(ECPoint[] points)
        {
            if (points == null)
                throw new ArgumentNullException("points");

            for (int i = 0; i < points.Length; ++i)
            {
                ECPoint point = points[i];
                if (null != point && this != point.Curve)
                    throw new ArgumentException("entries must be null or on this curve", "points");
            }
        }

        public virtual bool Equals(ECCurve other)
        {
            if (this == other)
                return true;
            if (null == other)
                return false;
            return Field.Equals(other.Field)
                && A.Equals(other.A)
                && B.Equals(other.B);
        }

        public override bool Equals(object obj) 
        {
            return Equals(obj as ECCurve);
        }

        public override int GetHashCode()
        {
            return Field.GetHashCode()
                ^ Integers.RotateLeft(A.GetHashCode(), 8)
                ^ Integers.RotateLeft(B.GetHashCode(), 16);
        }

        protected abstract ECPoint DecompressPoint(int yTilde, BigInteger X1);

        /**
         * Sets the default <code>ECMultiplier</code>, unless already set. 
         */
        public virtual ECMultiplier GetMultiplier()
        {
            lock (this)
            {
                if (this.m_multiplier == null)
                {
                    this.m_multiplier = CreateDefaultMultiplier();
                }
                return this.m_multiplier;
            }
        }

        /**
         * Decode a point on this curve from its ASN.1 encoding. The different
         * encodings are taken account of, including point compression for
         * <code>F<sub>p</sub></code> (X9.62 s 4.2.1 pg 17).
         * @return The decoded point.
         */
        public virtual ECPoint DecodePoint(byte[] encoded)
        {
            ECPoint p = null;
            int expectedLength = (FieldSize + 7) / 8;

            switch (encoded[0])
            {
                case 0x00: // infinity
                {
                    if (encoded.Length != 1)
                        throw new ArgumentException("Incorrect length for infinity encoding", "encoded");

                    p = Infinity;
                    break;
                }

                case 0x02: // compressed
                case 0x03: // compressed
                {
                    if (encoded.Length != (expectedLength + 1))
                        throw new ArgumentException("Incorrect length for compressed encoding", "encoded");

                    int yTilde = encoded[0] & 1;
                    BigInteger X1 = new BigInteger(1, encoded, 1, expectedLength);

                    p = DecompressPoint(yTilde, X1);
                    break;
                }

                case 0x04: // uncompressed
                case 0x06: // hybrid
                case 0x07: // hybrid
                {
                    if (encoded.Length != (2 * expectedLength + 1))
                        throw new ArgumentException("Incorrect length for uncompressed/hybrid encoding", "encoded");

                    BigInteger X1 = new BigInteger(1, encoded, 1, expectedLength);
                    BigInteger Y1 = new BigInteger(1, encoded, 1 + expectedLength, expectedLength);

                    p = CreatePoint(X1, Y1, false);
                    break;
                }

                default:
                    throw new FormatException("Invalid point encoding " + encoded[0]);
            }

            return p;
        }
    }

    /**
     * Elliptic curve over Fp
     */
    public class FpCurve
        : ECCurve
    {
        private const int FP_DEFAULT_COORDS = COORD_HOMOGENEOUS;

        protected readonly BigInteger m_q, m_r;
        protected readonly FpPoint m_infinity;

        public FpCurve(BigInteger q, BigInteger a, BigInteger b)
            : base(FiniteFields.GetPrimeField(q))
        {
            this.m_q = q;
            this.m_r = FpFieldElement.CalculateResidue(q);
            this.m_infinity = new FpPoint(this, null, null);

            this.m_a = FromBigInteger(a);
            this.m_b = FromBigInteger(b);
            this.m_coord = FP_DEFAULT_COORDS;
        }

        protected FpCurve(BigInteger q, BigInteger r, ECFieldElement a, ECFieldElement b)
            : base(FiniteFields.GetPrimeField(q))
        {
            this.m_q = q;
            this.m_r = r;
            this.m_infinity = new FpPoint(this, null, null);

            this.m_a = a;
            this.m_b = b;
            this.m_coord = FP_DEFAULT_COORDS;
        }

        protected override ECCurve CloneCurve()
        {
            return new FpCurve(m_q, m_r, m_a, m_b);
        }

        public override bool SupportsCoordinateSystem(int coord)
        {
            switch (coord)
            {
                case COORD_AFFINE:
                case COORD_HOMOGENEOUS:
                //case COORD_JACOBIAN:
                //case COORD_JACOBIAN_MODIFIED:
                    return true;
                default:
                    return false;
            }
        }

        public virtual BigInteger Q
        {
            get { return m_q; }
        }

        public override ECPoint Infinity
        {
            get { return m_infinity; }
        }

        public override int FieldSize
        {
            get { return m_q.BitLength; }
        }

        public override ECFieldElement FromBigInteger(BigInteger x)
        {
            return new FpFieldElement(this.m_q, this.m_r, x);
        }

        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
        {
            return new FpPoint(this, x, y, withCompression);
        }

        public override ECPoint CreatePoint(
            BigInteger	X1,
            BigInteger	Y1,
            bool		withCompression)
        {
            // TODO Validation of X1, Y1?
            return new FpPoint(
                this,
                FromBigInteger(X1),
                FromBigInteger(Y1),
                withCompression);
        }

        protected override ECPoint DecompressPoint(
            int			yTilde,
            BigInteger	X1)
        {
            ECFieldElement x = FromBigInteger(X1);
            ECFieldElement alpha = x.Multiply(x.Square().Add(m_a)).Add(m_b);
            ECFieldElement beta = alpha.Sqrt();

            //
            // if we can't find a sqrt we haven't got a point on the
            // curve - run!
            //
            if (beta == null)
                throw new ArithmeticException("Invalid point compression");

            BigInteger betaValue = beta.ToBigInteger();
            int bit0 = betaValue.TestBit(0) ? 1 : 0;

            if (bit0 != yTilde)
            {
                // Use the other root
                beta = beta.Negate();
            }

            return new FpPoint(this, x, beta, true);
        }
    }

    /**
     * Elliptic curves over F2m. The Weierstrass equation is given by
     * <code>y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b</code>.
     */
    public class F2mCurve : ECCurve
    {
        private const int F2M_DEFAULT_COORDS = COORD_AFFINE;

        private static IFiniteField BuildField(int m, int k1, int k2, int k3)
        {
            if (k1 == 0)
            {
                throw new ArgumentException("k1 must be > 0");
            }

            if (k2 == 0)
            {
                if (k3 != 0)
                {
                    throw new ArgumentException("k3 must be 0 if k2 == 0");
                }

                return FiniteFields.GetBinaryExtensionField(new int[]{ 0, k1, m });
            }

            if (k2 <= k1)
            {
                throw new ArgumentException("k2 must be > k1");
            }

            if (k3 <= k2)
            {
                throw new ArgumentException("k3 must be > k2");
            }

            return FiniteFields.GetBinaryExtensionField(new int[]{ 0, k1, k2, k3, m });
        }

        /**
         * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
         */
        private readonly int m;

        /**
         * TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction polynomial
         * <code>f(z)</code>.<br/>
         * PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br/>
         */
        private readonly int k1;

        /**
         * TPB: Always set to <code>0</code><br/>
         * PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br/>
         */
        private readonly int k2;

        /**
         * TPB: Always set to <code>0</code><br/>
         * PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br/>
         */
        private readonly int k3;

        /**
         * The order of the base point of the curve.
         */
        private readonly BigInteger n;

        /**
         * The cofactor of the curve.
         */
        private readonly BigInteger h;

        /**
         * The point at infinity on this curve.
         */
        protected readonly F2mPoint m_infinity;

        /**
         * The parameter <code>&#956;</code> of the elliptic curve if this is
         * a Koblitz curve.
         */
        private sbyte mu = 0;

        /**
         * The auxiliary values <code>s<sub>0</sub></code> and
         * <code>s<sub>1</sub></code> used for partial modular reduction for
         * Koblitz curves.
         */
        private BigInteger[] si = null;

        /**
         * Constructor for Trinomial Polynomial Basis (TPB).
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction
         * polynomial <code>f(z)</code>.
         * @param a The coefficient <code>a</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param b The coefficient <code>b</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         */
        public F2mCurve(
            int			m,
            int			k,
            BigInteger	a,
            BigInteger	b)
            : this(m, k, 0, 0, a, b, null, null)
        {
        }

        /**
         * Constructor for Trinomial Polynomial Basis (TPB).
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction
         * polynomial <code>f(z)</code>.
         * @param a The coefficient <code>a</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param b The coefficient <code>b</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param n The order of the main subgroup of the elliptic curve.
         * @param h The cofactor of the elliptic curve, i.e.
         * <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>.
         */
        public F2mCurve(
            int			m, 
            int			k, 
            BigInteger	a, 
            BigInteger	b,
            BigInteger	n,
            BigInteger	h)
            : this(m, k, 0, 0, a, b, n, h)
        {
        }

        /**
         * Constructor for Pentanomial Polynomial Basis (PPB).
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
         * @param a The coefficient <code>a</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param b The coefficient <code>b</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         */
        public F2mCurve(
            int			m,
            int			k1,
            int			k2,
            int			k3,
            BigInteger	a,
            BigInteger	b)
            : this(m, k1, k2, k3, a, b, null, null)
        {
        }

        /**
         * Constructor for Pentanomial Polynomial Basis (PPB).
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
         * @param a The coefficient <code>a</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param b The coefficient <code>b</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param n The order of the main subgroup of the elliptic curve.
         * @param h The cofactor of the elliptic curve, i.e.
         * <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>.
         */
        public F2mCurve(
            int			m, 
            int			k1, 
            int			k2, 
            int			k3,
            BigInteger	a, 
            BigInteger	b,
            BigInteger	n,
            BigInteger	h)
            : base(BuildField(m, k1, k2, k3))
        {
            this.m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
            this.n = n;
            this.h = h;
            this.m_infinity = new F2mPoint(this, null, null);

            if (k1 == 0)
                throw new ArgumentException("k1 must be > 0");

            if (k2 == 0)
            {
                if (k3 != 0)
                    throw new ArgumentException("k3 must be 0 if k2 == 0");
            }
            else
            {
                if (k2 <= k1)
                    throw new ArgumentException("k2 must be > k1");

                if (k3 <= k2)
                    throw new ArgumentException("k3 must be > k2");
            }

            this.m_a = FromBigInteger(a);
            this.m_b = FromBigInteger(b);
            this.m_coord = F2M_DEFAULT_COORDS;
        }

        protected F2mCurve(int m, int k1, int k2, int k3, ECFieldElement a, ECFieldElement b, BigInteger order, BigInteger cofactor)
            : base(BuildField(m, k1, k2, k3))
        {
            this.m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
            this.n = order;
            this.h = cofactor;

            this.m_infinity = new F2mPoint(this, null, null);
            this.m_a = a;
            this.m_b = b;
            this.m_coord = F2M_DEFAULT_COORDS;
        }

        protected override ECCurve CloneCurve()
        {
            return new F2mCurve(m, k1, k2, k3, m_a, m_b, n, h);
        }

        protected override ECMultiplier CreateDefaultMultiplier()
        {
            if (IsKoblitz)
            {
                return new WTauNafMultiplier();
            }

            return base.CreateDefaultMultiplier();
        }

        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
        {
            return new F2mPoint(this, x, y, withCompression);
        }

        public override ECPoint Infinity
        {
            get { return m_infinity; }
        }

        public override int FieldSize
        {
            get { return m; }
        }

        public override ECFieldElement FromBigInteger(BigInteger x)
        {
            return new F2mFieldElement(this.m, this.k1, this.k2, this.k3, x);
        }

        /**
         * Returns true if this is a Koblitz curve (ABC curve).
         * @return true if this is a Koblitz curve (ABC curve), false otherwise
         */
        public virtual bool IsKoblitz
        {
            get
            {
                return n != null && h != null && m_a.BitLength <= 1 && m_b.IsOne;
            }
        }

        /**
         * Returns the parameter <code>&#956;</code> of the elliptic curve.
         * @return <code>&#956;</code> of the elliptic curve.
         * @throws ArgumentException if the given ECCurve is not a
         * Koblitz curve.
         */
        internal virtual sbyte GetMu()
        {
            if (mu == 0)
            {
                lock (this)
                {
                    if (mu == 0)
                    {
                        mu = Tnaf.GetMu(this);
                    }
                }
            }

            return mu;
        }

        /**
         * @return the auxiliary values <code>s<sub>0</sub></code> and
         * <code>s<sub>1</sub></code> used for partial modular reduction for
         * Koblitz curves.
         */
        internal virtual BigInteger[] GetSi()
        {
            if (si == null)
            {
                lock (this)
                {
                    if (si == null)
                    {
                        si = Tnaf.GetSi(this);
                    }
                }
            }
            return si;
        }

        public override ECPoint CreatePoint(
            BigInteger	X1,
            BigInteger	Y1,
            bool		withCompression)
        {
            // TODO Validation of X1, Y1?
            return new F2mPoint(
                this,
                FromBigInteger(X1),
                FromBigInteger(Y1),
                withCompression);
        }

        protected override ECPoint DecompressPoint(
            int			yTilde,
            BigInteger	X1)
        {
            ECFieldElement xp = FromBigInteger(X1);
            ECFieldElement yp = null;
            if (xp.ToBigInteger().SignValue == 0)
            {
                yp = (F2mFieldElement)m_b;
                for (int i = 0; i < m - 1; i++)
                {
                    yp = yp.Square();
                }
            }
            else
            {
                ECFieldElement beta = xp.Add(m_a).Add(m_b.Multiply(xp.Square().Invert()));
                ECFieldElement z = SolveQuadradicEquation(beta);

                if (z == null)
                    throw new ArithmeticException("Invalid point compression");

                int zBit = z.ToBigInteger().TestBit(0) ? 1 : 0;
                if (zBit != yTilde)
                {
                    z = z.Add(FromBigInteger(BigInteger.One));
                }

                yp = xp.Multiply(z);
            }

            return new F2mPoint(this, xp, yp, true);
        }

        /**
         * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
         * D.1.6) The other solution is <code>z + 1</code>.
         *
         * @param beta
         *            The value to solve the qradratic equation for.
         * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
         *         <code>null</code> if no solution exists.
         */
        private ECFieldElement SolveQuadradicEquation(ECFieldElement beta)
        {
            if (beta.IsZero)
            {
                return beta;
            }

            ECFieldElement zeroElement = FromBigInteger(BigInteger.Zero);

            ECFieldElement z = null;
            ECFieldElement gamma = null;

            Random rand = new Random();
            do
            {
                ECFieldElement t = FromBigInteger(new BigInteger(m, rand));
                z = zeroElement;
                ECFieldElement w = beta;
                for (int i = 1; i <= m - 1; i++)
                {
                    ECFieldElement w2 = w.Square();
                    z = z.Square().Add(w2.Multiply(t));
                    w = w2.Add(beta);
                }
                if (!w.IsZero)
                {
                    return null;
                }
                gamma = z.Square().Add(z);
            }
            while (gamma.IsZero);

            return z;
        }

        public int M
        {
            get { return m; }
        }

        /**
         * Return true if curve uses a Trinomial basis.
         *
         * @return true if curve Trinomial, false otherwise.
         */
        public bool IsTrinomial()
        {
            return k2 == 0 && k3 == 0;
        }

        public int K1
        {
            get { return k1; }
        }

        public int K2
        {
            get { return k2; }
        }

        public int K3
        {
            get { return k3; }
        }

        public BigInteger N
        {
            get { return n; }
        }

        public BigInteger H
        {
            get { return h; }
        }
    }
}
