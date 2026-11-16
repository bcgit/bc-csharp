using System;
using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC
{
    /// <summary>Base class for points on elliptic curves.</summary>
    public abstract class ECPoint
    {
        /// <summary>The empty array of additional coordinates.</summary>
        protected static readonly ECFieldElement[] EMPTY_ZS = new ECFieldElement[0];

        /// <summary>Get the initial additional coordinates for a point on a curve.</summary>
        /// <param name="curve">The curve.</param>
        /// <returns>The coordinates.</returns>
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
                return new ECFieldElement[]{ one };
            case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
                return new ECFieldElement[]{ one, one, one };
            case ECCurve.COORD_JACOBIAN_MODIFIED:
                return new ECFieldElement[]{ one, curve.A };
            default:
                throw new ArgumentException("unknown coordinate system");
            }
        }

        /// <summary>The curve.</summary>
        protected internal readonly ECCurve m_curve;
        /// <summary>The y.</summary>
        protected internal readonly ECFieldElement m_x, m_y;
        /// <summary>The zs.</summary>
        protected internal readonly ECFieldElement[] m_zs;

        /// <summary>The pre comp table.</summary>
        protected internal IDictionary<string, PreCompInfo> m_preCompTable = null;

        /// <summary>Create a new <see cref="ECPoint"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="x">The first operand.</param>
        /// <param name="y">The second operand.</param>
        protected ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : this(curve, x, y, GetInitialZCoords(curve))
        {
        }

        internal ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
        {
            // TODO[api] Require all parameters to be non-null

            m_curve = curve;
            m_x = x;
            m_y = y;
            m_zs = zs;
        }

        /// <summary>Determine whether the point satisfies the equation of its curve.</summary>
        /// <returns>true if it does, false otherwise.</returns>
        protected abstract bool SatisfiesCurveEquation();

        /// <summary>Determine whether the point has the order of the curve subgroup.</summary>
        /// <returns>true if it does, false otherwise.</returns>
        protected virtual bool SatisfiesOrder()
        {
            if (BigInteger.One.Equals(Curve.Cofactor))
                return true;

            BigInteger n = Curve.Order;

            // TODO[api] Require order to be available for all curves

            return n == null || ECAlgorithms.ReferenceMultiply(this, n).IsInfinity;
        }

        /// <summary>Return the detached point.</summary>
        [Obsolete("Will be removed")]
        public ECPoint GetDetachedPoint() => Normalize().Detach();

        /// <summary>Gets the curve.</summary>
        public virtual ECCurve Curve => m_curve;

        /// <summary>
        /// Create a copy of this point that is not attached to the precomputation caches of its curve.
        /// </summary>
        /// <returns>The copy.</returns>
        [Obsolete("Will be removed")]
        protected abstract ECPoint Detach();

        /// <summary>Gets the curve coordinate system.</summary>
        protected virtual int CurveCoordinateSystem
        {
            get
            {
                // Cope with null curve, most commonly used by implicitlyCa
                return null == m_curve ? ECCurve.COORD_AFFINE : m_curve.CoordinateSystem;
            }
        }

        /// <summary>Returns the affine x-coordinate after checking that this point is normalized.</summary>
        public virtual ECFieldElement AffineXCoord
        {
            get
            {
                CheckNormalized();
                return XCoord;
            }
        }

        /// <summary>Returns the affine y-coordinate after checking that this point is normalized.</summary>
        public virtual ECFieldElement AffineYCoord
        {
            get
            {
                CheckNormalized();
                return YCoord;
            }
        }

        /// <summary>Returnss the x-coordinate.</summary>
        /// <remarks>
        /// Caution: depending on the curve's coordinate system, this may not be the same value as in an affine
        /// coordinate system; use <see cref="Normalize()"/> to get a point where the coordinates have their affine
        /// values, or use <see cref="AffineXCoord"/> if you expect the point to already have been normalized.
        /// </remarks>
        public virtual ECFieldElement XCoord => m_x;

        /// <summary>Returnss the y-coordinate.</summary>
        /// <remarks>
        /// Caution: depending on the curve's coordinate system, this may not be the same value as in an affine
        /// coordinate system; use <see cref="Normalize()"/> to get a point where the coordinates have their affine
        /// values, or use <see cref="AffineYCoord"/> if you expect the point to already have been normalized.
        /// </remarks>
        public virtual ECFieldElement YCoord => m_y;

        /// <summary>Get an additional coordinate of this point.</summary>
        /// <param name="index">The index of the coordinate.</param>
        /// <returns>The coordinate.</returns>
        public virtual ECFieldElement GetZCoord(int index)
        {
            return (index < 0 || index >= m_zs.Length) ? null : m_zs[index];
        }

        /// <summary>Return the z coords.</summary>
        public virtual ECFieldElement[] GetZCoords() =>
            m_zs.Length == 0 ? EMPTY_ZS : Arrays.CopyBuffer(m_zs);

        /// <summary>Gets the raw x coord.</summary>
        protected internal ECFieldElement RawXCoord => m_x;

        /// <summary>Gets the raw y coord.</summary>
        protected internal ECFieldElement RawYCoord => m_y;

        /// <summary>Gets the raw z coords.</summary>
        protected internal ECFieldElement[] RawZCoords => m_zs;

        /// <summary>Check that this point is normalized.</summary>
        /// <exception cref="InvalidOperationException">The point is not normalized.</exception>
        protected virtual void CheckNormalized()
        {
            if (!IsNormalized())
                throw new InvalidOperationException("point not in normal form");
        }

        /// <summary>Determine whether this point is normalized, that is, in affine form.</summary>
        /// <returns>true if the point is normalized, false otherwise.</returns>
        public virtual bool IsNormalized()
        {
            int coord = CurveCoordinateSystem;

            return coord == ECCurve.COORD_AFFINE
                || coord == ECCurve.COORD_LAMBDA_AFFINE
                || IsInfinity
                || RawZCoords[0].IsOne;
        }

        /// <summary>
        /// Normalization ensures that any projective coordinate is 1, and therefore that the x, y coordinates reflect
        /// those of the equivalent point in an affine coordinate system.
        /// </summary>
        public virtual ECPoint Normalize()
        {
            if (IsInfinity)
                return this;

            switch (CurveCoordinateSystem)
            {
            case ECCurve.COORD_AFFINE:
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                return this;
            }
            default:
            {
                ECFieldElement z = RawZCoords[0];
                if (z.IsOne)
                    return this;

                if (null == m_curve)
                    throw new InvalidOperationException("Detached points must be in affine coordinates");

                /*
                 * Use blinding to avoid the side-channel leak identified and analyzed in the paper
                 * "Yet another GCD based inversion side-channel affecting ECC implementations" by Nir
                 * Drucker and Shay Gueron.
                 *
                 * To blind the calculation of z^-1, choose a multiplicative (i.e. non-zero) field
                 * element 'b' uniformly at random, then calculate the result instead as (z * b)^-1 * b.
                 * Any side-channel in the implementation of 'inverse' now only leaks information about
                 * the value (z * b), and no longer reveals information about 'z' itself.
                 */
                ECFieldElement b = m_curve.RandomFieldElementMult(SecureRandom.ArbitraryRandom);
                ECFieldElement zInv = z.Multiply(b).Invert().Multiply(b);
                return Normalize(zInv);
            }
            }
        }

        internal virtual ECPoint Normalize(ECFieldElement zInv)
        {
            switch (CurveCoordinateSystem)
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

        /// <summary>Create a point with the affine coordinates scaled.</summary>
        /// <param name="sx">The scale for the x-coordinate.</param>
        /// <param name="sy">The scale for the y-coordinate.</param>
        /// <returns>The new point.</returns>
        protected virtual ECPoint CreateScaledPoint(ECFieldElement sx, ECFieldElement sy) =>
            Curve.CreateRawPoint(RawXCoord.Multiply(sx), RawYCoord.Multiply(sy));

        /// <summary>Gets a value indicating whether this is infinity.</summary>
        public bool IsInfinity => m_x == null && m_y == null;

        /// <summary>Determine whether this point is valid: on the curve and of the correct order.</summary>
        /// <returns>true if the point is valid, false otherwise.</returns>
        public bool IsValid() => ImplIsValid(false, true);

        internal bool IsValidPartial() => ImplIsValid(false, false);

        internal bool ImplIsValid(bool decompressed, bool checkOrder)
        {
            if (IsInfinity)
                return true;

            ValidityCallback callback = new ValidityCallback(this, decompressed, checkOrder);
            ValidityPreCompInfo validity = (ValidityPreCompInfo)Curve.Precompute(this, ValidityPreCompInfo.PRECOMP_NAME, callback);
            return !validity.HasFailed();
        }

        /// <summary>Multiply the x-coordinate by a scale factor.</summary>
        /// <param name="scale">The scale factor.</param>
        /// <returns>The new point.</returns>
        public virtual ECPoint ScaleX(ECFieldElement scale)
        {
            return IsInfinity
                ? this
                : Curve.CreateRawPoint(RawXCoord.Multiply(scale), RawYCoord, RawZCoords);
        }

        /// <summary>Multiply the x-coordinate by a scale factor and negate the y-coordinate.</summary>
        /// <param name="scale">The scale factor.</param>
        /// <returns>The new point.</returns>
        public virtual ECPoint ScaleXNegateY(ECFieldElement scale)
        {
            return IsInfinity
                ? this
                : Curve.CreateRawPoint(RawXCoord.Multiply(scale), RawYCoord.Negate(), RawZCoords);
        }

        /// <summary>Multiply the y-coordinate by a scale factor.</summary>
        /// <param name="scale">The scale factor.</param>
        /// <returns>The new point.</returns>
        public virtual ECPoint ScaleY(ECFieldElement scale)
        {
            return IsInfinity
                ? this
                : Curve.CreateRawPoint(RawXCoord, RawYCoord.Multiply(scale), RawZCoords);
        }

        /// <summary>Multiply the y-coordinate by a scale factor and negate the x-coordinate.</summary>
        /// <param name="scale">The scale factor.</param>
        /// <returns>The new point.</returns>
        public virtual ECPoint ScaleYNegateX(ECFieldElement scale)
        {
            return IsInfinity
                ? this
                : Curve.CreateRawPoint(RawXCoord.Negate(), RawYCoord.Multiply(scale), RawZCoords);
        }

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            return Equals(obj as ECPoint);
        }

        /// <summary>Determine whether this point is equal to another.</summary>
        /// <param name="other">The point to compare with.</param>
        /// <returns>true if the points are equal, false otherwise.</returns>
        public virtual bool Equals(ECPoint other)
        {
            if (this == other)
                return true;
            if (null == other)
                return false;

            ECCurve c1 = Curve, c2 = other.Curve;
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

                ECPoint[] points = new ECPoint[]{ this, c1.ImportPoint(p2) };

                // TODO This is a little strong, really only requires coZNormalizeAll to get Zs equal
                c1.NormalizeAll(points);

                p1 = points[0];
                p2 = points[1];
            }

            return p1.XCoord.Equals(p2.XCoord) && p1.YCoord.Equals(p2.YCoord);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            ECCurve c = Curve;
            int hc = (null == c) ? 0 : ~c.GetHashCode();

            if (!IsInfinity)
            {
                // TODO Consider just requiring already normalized, to avoid silent performance degradation

                ECPoint p = Normalize();

                hc ^= p.XCoord.GetHashCode() * 17;
                hc ^= p.YCoord.GetHashCode() * 257;
            }

            return hc;
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            if (IsInfinity)
                return "INF";

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

        /// <summary>Return the encoded.</summary>
        public virtual byte[] GetEncoded() => GetEncoded(false);

        /// <summary>Get the encoding of this point.</summary>
        /// <param name="compressed">true for the compressed encoding, false for the uncompressed encoding.</param>
        /// <returns>The encoding.</returns>
        public abstract byte[] GetEncoded(bool compressed);

        /// <summary>Get the length in bytes of the encoding of this point.</summary>
        /// <param name="compressed">true for the compressed encoding, false for the uncompressed encoding.</param>
        /// <returns>The length in bytes.</returns>
        public abstract int GetEncodedLength(bool compressed);

        /// <summary>Write the encoding of this point.</summary>
        /// <param name="compressed">true for the compressed encoding, false for the uncompressed encoding.</param>
        /// <param name="buf">The buffer to write to.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which to write.</param>
        public abstract void EncodeTo(bool compressed, byte[] buf, int off);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Write the encoding of this point.</summary>
        /// <param name="compressed">true for the compressed encoding, false for the uncompressed encoding.</param>
        /// <param name="buf">The buffer to write to.</param>
        public abstract void EncodeTo(bool compressed, Span<byte> buf);
#endif

        /// <summary>Gets the compression y tilde.</summary>
        protected internal abstract bool CompressionYTilde { get; }

        /// <summary>Return the sum of this point and another.</summary>
        /// <param name="b">The other point.</param>
        /// <returns>The sum.</returns>
        public abstract ECPoint Add(ECPoint b);
        /// <summary>Return the difference of this point and another.</summary>
        /// <param name="b">The point to subtract.</param>
        /// <returns>The difference.</returns>
        public abstract ECPoint Subtract(ECPoint b);
        /// <summary>Return the negation of this point.</summary>
        /// <returns>The negation.</returns>
        public abstract ECPoint Negate();

        /// <summary>Return this point multiplied by 2^e.</summary>
        /// <param name="e">The exponent.</param>
        /// <returns>The result.</returns>
        public virtual ECPoint TimesPow2(int e)
        {
            if (e < 0)
                throw new ArgumentException("cannot be negative", nameof(e));

            ECPoint p = this;
            while (--e >= 0)
            {
                p = p.Twice();
            }
            return p;
        }

        /// <summary>Return this point doubled.</summary>
        /// <returns>The doubled point.</returns>
        public abstract ECPoint Twice();
        /// <summary>Return this point multiplied by a scalar.</summary>
        /// <param name="b">The scalar.</param>
        /// <returns>The product.</returns>
        public abstract ECPoint Multiply(BigInteger b);

        /// <summary>Return twice this point plus another point.</summary>
        /// <param name="b">The point to add.</param>
        /// <returns>The result.</returns>
        public virtual ECPoint TwicePlus(ECPoint b) => Twice().Add(b);

        /// <summary>Return this point multiplied by three.</summary>
        /// <returns>The result.</returns>
        public virtual ECPoint ThreeTimes() => TwicePlus(this);

        private class ValidityCallback
            : IPreCompCallback
        {
            private readonly ECPoint m_outer;
            private readonly bool m_decompressed, m_checkOrder;

            internal ValidityCallback(ECPoint outer, bool decompressed, bool checkOrder)
            {
                m_outer = outer;
                m_decompressed = decompressed;
                m_checkOrder = checkOrder;
            }

            public PreCompInfo Precompute(PreCompInfo existing)
            {
                ValidityPreCompInfo info = existing as ValidityPreCompInfo ?? new ValidityPreCompInfo();

                if (info.HasFailed())
                    return info;

                if (!info.HasCurveEquationPassed())
                {
                    if (!m_decompressed && !m_outer.SatisfiesCurveEquation())
                    {
                        info.ReportFailed();
                        return info;
                    }
                    info.ReportCurveEquationPassed();
                }
                if (m_checkOrder && !info.HasOrderPassed())
                {
                    if (!m_outer.SatisfiesOrder())
                    {
                        info.ReportFailed();
                        return info;
                    }
                    info.ReportOrderPassed();
                }
                return info;
            }
        }
    }

    /// <summary>Base class for elliptic curve points.</summary>
    public abstract class ECPointBase
        : ECPoint
    {
        /// <summary>Create a new <see cref="ECPointBase"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="x">The first operand.</param>
        /// <param name="y">The second operand.</param>
        protected internal ECPointBase(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : base(curve, x, y)
        {
        }

        /// <summary>Create a new <see cref="ECPointBase"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="x">The first operand.</param>
        /// <param name="y">The second operand.</param>
        /// <param name="zs">The zs.</param>
        protected internal ECPointBase(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
            : base(curve, x, y, zs)
        {
        }

        /**
         * return the field element encoded with point compression. (S 4.3.6)
         */
        public override byte[] GetEncoded(bool compressed)
        {
            if (IsInfinity)
                return new byte[1];

            int encodedLength = GetEncodedLength(compressed);
            byte[] buf = new byte[encodedLength];
            EncodeTo(compressed, buf, 0);
            return buf;
        }

        /// <inheritdoc/>
        public override int GetEncodedLength(bool compressed)
        {
            if (IsInfinity)
                return 1;

            if (compressed)
                return 1 + XCoord.GetEncodedLength();

            return 1 + XCoord.GetEncodedLength() + YCoord.GetEncodedLength();
        }

        /// <inheritdoc/>
        public override void EncodeTo(bool compressed, byte[] buf, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            EncodeTo(compressed, buf.AsSpan(off));
#else
            if (IsInfinity)
            {
                buf[off] = 0x00;
                return;
            }

            ECPoint normed = Normalize();
            ECFieldElement X = normed.XCoord, Y = normed.YCoord;

            if (compressed)
            {
                buf[off] = (byte)(normed.CompressionYTilde ? 0x03 : 0x02);
                X.EncodeTo(buf, off + 1);
                return;
            }

            buf[off] = 0x04;
            X.EncodeTo(buf, off + 1);
            Y.EncodeTo(buf, off + 1 + X.GetEncodedLength());
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void EncodeTo(bool compressed, Span<byte> buf)
        {
            if (IsInfinity)
            {
                buf[0] = 0x00;
                return;
            }

            ECPoint normed = Normalize();
            ECFieldElement X = normed.XCoord, Y = normed.YCoord;

            if (compressed)
            {
                buf[0] = (byte)(normed.CompressionYTilde ? 0x03 : 0x02);
                X.EncodeTo(buf[1..]);
                return;
            }

            buf[0] = 0x04;
            X.EncodeTo(buf[1..]);
            Y.EncodeTo(buf[(1 + X.GetEncodedLength())..]);
        }
#endif

        /// <summary>Multiplies this <see cref="ECPoint"/> by the given scalar.</summary>
        public override ECPoint Multiply(BigInteger k) => Curve.GetMultiplier().Multiply(this, k);
    }

    /// <summary>Base class for points on curves over a prime field.</summary>
    public abstract class AbstractFpPoint
        : ECPointBase
    {
        /// <summary>Create a new <see cref="AbstractFpPoint"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="x">The first operand.</param>
        /// <param name="y">The second operand.</param>
        protected AbstractFpPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : base(curve, x, y)
        {
        }

        /// <summary>Create a new <see cref="AbstractFpPoint"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="x">The first operand.</param>
        /// <param name="y">The second operand.</param>
        /// <param name="zs">The zs.</param>
        protected AbstractFpPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
            : base(curve, x, y, zs)
        {
        }

        /// <inheritdoc/>
        protected internal override bool CompressionYTilde => AffineYCoord.TestBitZero();

        /// <inheritdoc/>
        protected override bool SatisfiesCurveEquation()
        {
            ECFieldElement X = RawXCoord, Y = RawYCoord, A = Curve.A, B = Curve.B;
            ECFieldElement lhs = Y.Square();

            switch (CurveCoordinateSystem)
            {
            case ECCurve.COORD_AFFINE:
                break;
            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Z = RawZCoords[0];
                if (!Z.IsOne)
                {
                    ECFieldElement Z2 = Z.Square(), Z3 = Z.Multiply(Z2);
                    lhs = lhs.Multiply(Z);
                    A = A.Multiply(Z2);
                    B = B.Multiply(Z3);
                }
                break;
            }
            case ECCurve.COORD_JACOBIAN:
            case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                ECFieldElement Z = RawZCoords[0];
                if (!Z.IsOne)
                {
                    ECFieldElement Z2 = Z.Square(), Z4 = Z2.Square(), Z6 = Z2.Multiply(Z4);
                    A = A.Multiply(Z4);
                    B = B.Multiply(Z6);
                }
                break;
            }
            default:
                throw new InvalidOperationException("unsupported coordinate system");
            }

            ECFieldElement rhs = X.Square().Add(A).Multiply(X).Add(B);
            return lhs.Equals(rhs);
        }

        /// <inheritdoc/>
        public override ECPoint Subtract(ECPoint b)
        {
            if (b.IsInfinity)
                return this;

            // Add -b
            return Add(b.Negate());
        }
    }

    /**
     * Elliptic curve points over Fp
     */
    public class FpPoint
        : AbstractFpPoint
    {
        internal FpPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : base(curve, x, y)
        {
            if ((x == null) != (y == null))
                throw new ArgumentException("Exactly one of the field elements is null");
        }

        internal FpPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
            : base(curve, x, y, zs)
        {
        }

        /// <inheritdoc/>
        [Obsolete("Will be removed")]
        protected override ECPoint Detach() => new FpPoint(null, AffineXCoord, AffineYCoord);

        /// <inheritdoc/>
        public override ECFieldElement GetZCoord(int index)
        {
            if (index == 1 && ECCurve.COORD_JACOBIAN_MODIFIED == CurveCoordinateSystem)
                return GetJacobianModifiedW();

            return base.GetZCoord(index);
        }

        /// <inheritdoc/>
        // B.3 pg 62
        public override ECPoint Add(ECPoint b)
        {
            if (IsInfinity)
                return b;
            if (b.IsInfinity)
                return this;
            if (this == b)
                return Twice();

            ECCurve curve = Curve;
            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = RawXCoord, Y1 = RawYCoord;
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

                return new FpPoint(Curve, X3, Y3);
            }

            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Z1 = RawZCoords[0];
                ECFieldElement Z2 = b.RawZCoords[0];

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
                        return Twice();
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
                ECFieldElement Y3 = vSquaredV2.Subtract(A).MultiplyMinusProduct(u, u2, vCubed);
                ECFieldElement Z3 = vCubed.Multiply(w);

                return new FpPoint(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }

            case ECCurve.COORD_JACOBIAN:
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                ECFieldElement Z1 = RawZCoords[0];
                ECFieldElement Z2 = b.RawZCoords[0];

                bool Z1IsOne = Z1.IsOne;

                ECFieldElement X3, Y3, Z3, Z3Squared = null;

                if (!Z1IsOne && Z1.Equals(Z2))
                {
                    // TODO Make this available as public method coZAdd?

                    ECFieldElement dx = X1.Subtract(X2), dy = Y1.Subtract(Y2);
                    if (dx.IsZero)
                    {
                        if (dy.IsZero)
                            return Twice();

                        return curve.Infinity;
                    }

                    ECFieldElement C = dx.Square();
                    ECFieldElement W1 = X1.Multiply(C), W2 = X2.Multiply(C);
                    ECFieldElement A1 = W1.Subtract(W2).Multiply(Y1);

                    X3 = dy.Square().Subtract(W1).Subtract(W2);
                    Y3 = W1.Subtract(X3).Multiply(dy).Subtract(A1);
                    Z3 = dx;

                    if (Z1IsOne)
                    {
                        Z3Squared = C;
                    }
                    else
                    {
                        Z3 = Z3.Multiply(Z1);
                    }
                }
                else
                {
                    ECFieldElement Z1Squared, U2, S2;
                    if (Z1IsOne)
                    {
                        Z1Squared = Z1; U2 = X2; S2 = Y2;
                    }
                    else
                    {
                        Z1Squared = Z1.Square();
                        U2 = Z1Squared.Multiply(X2);
                        ECFieldElement Z1Cubed = Z1Squared.Multiply(Z1);
                        S2 = Z1Cubed.Multiply(Y2);
                    }

                    bool Z2IsOne = Z2.IsOne;
                    ECFieldElement Z2Squared, U1, S1;
                    if (Z2IsOne)
                    {
                        Z2Squared = Z2; U1 = X1; S1 = Y1;
                    }
                    else
                    {
                        Z2Squared = Z2.Square();
                        U1 = Z2Squared.Multiply(X1);
                        ECFieldElement Z2Cubed = Z2Squared.Multiply(Z2);
                        S1 = Z2Cubed.Multiply(Y1);
                    }

                    ECFieldElement H = U1.Subtract(U2);
                    ECFieldElement R = S1.Subtract(S2);

                    // Check if b == this or b == -this
                    if (H.IsZero)
                    {
                        if (R.IsZero)
                        {
                            // this == b, i.e. this must be doubled
                            return Twice();
                        }

                        // this == -b, i.e. the result is the point at infinity
                        return curve.Infinity;
                    }

                    ECFieldElement HSquared = H.Square();
                    ECFieldElement G = HSquared.Multiply(H);
                    ECFieldElement V = HSquared.Multiply(U1);

                    X3 = R.Square().Add(G).Subtract(Two(V));
                    Y3 = V.Subtract(X3).MultiplyMinusProduct(R, G, S1);

                    Z3 = H;
                    if (!Z1IsOne)
                    {
                        Z3 = Z3.Multiply(Z1);
                    }
                    if (!Z2IsOne)
                    {
                        Z3 = Z3.Multiply(Z2);
                    }

                    // Alternative calculation of Z3 using fast square
                    //X3 = four(X3);
                    //Y3 = eight(Y3);
                    //Z3 = doubleProductFromSquares(Z1, Z2, Z1Squared, Z2Squared).Multiply(H);

                    if (Z3 == H)
                    {
                        Z3Squared = HSquared;
                    }
                }

                ECFieldElement[] zs;
                if (coord == ECCurve.COORD_JACOBIAN_MODIFIED)
                {
                    // TODO If the result will only be used in a subsequent addition, we don't need W3
                    ECFieldElement W3 = CalculateJacobianModifiedW(Z3, Z3Squared);

                    zs = new ECFieldElement[]{ Z3, W3 };
                }
                else
                {
                    zs = new ECFieldElement[]{ Z3 };
                }

                return new FpPoint(curve, X3, Y3, zs);
            }

            default:
            {
                throw new InvalidOperationException("unsupported coordinate system");
            }
            }
        }

        /// <inheritdoc/>
        // B.3 pg 62
        public override ECPoint Twice()
        {
            if (IsInfinity)
                return this;

            ECCurve curve = Curve;

            ECFieldElement Y1 = RawYCoord;
            if (Y1.IsZero)
                return curve.Infinity;

            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = RawXCoord;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement X1Squared = X1.Square();
                ECFieldElement gamma = Three(X1Squared).Add(Curve.A).Divide(Two(Y1));
                ECFieldElement X3 = gamma.Square().Subtract(Two(X1));
                ECFieldElement Y3 = gamma.Multiply(X1.Subtract(X3)).Subtract(Y1);

                return new FpPoint(Curve, X3, Y3);
            }

            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Z1 = RawZCoords[0];

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

                return new FpPoint(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }

            case ECCurve.COORD_JACOBIAN:
            {
                ECFieldElement Z1 = RawZCoords[0];

                bool Z1IsOne = Z1.IsOne;

                ECFieldElement Y1Squared = Y1.Square();
                ECFieldElement T = Y1Squared.Square();

                ECFieldElement a4 = curve.A;
                ECFieldElement a4Neg = a4.Negate();

                ECFieldElement M, S;
                if (a4Neg.ToBigInteger().Equals(BigInteger.Three))
                {
                    ECFieldElement Z1Squared = Z1IsOne ? Z1 : Z1.Square();
                    M = Three(X1.Add(Z1Squared).Multiply(X1.Subtract(Z1Squared)));
                    S = Four(Y1Squared.Multiply(X1));
                }
                else
                {
                    ECFieldElement X1Squared = X1.Square();
                    M = Three(X1Squared);
                    if (Z1IsOne)
                    {
                        M = M.Add(a4);
                    }
                    else if (!a4.IsZero)
                    {
                        ECFieldElement Z1Squared = Z1IsOne ? Z1 : Z1.Square();
                        ECFieldElement Z1Pow4 = Z1Squared.Square();
                        if (a4Neg.BitLength < a4.BitLength)
                        {
                            M = M.Subtract(Z1Pow4.Multiply(a4Neg));
                        }
                        else
                        {
                            M = M.Add(Z1Pow4.Multiply(a4));
                        }
                    }
                    //S = two(doubleProductFromSquares(X1, Y1Squared, X1Squared, T));
                    S = Four(X1.Multiply(Y1Squared));
                }

                ECFieldElement X3 = M.Square().Subtract(Two(S));
                ECFieldElement Y3 = S.Subtract(X3).Multiply(M).Subtract(Eight(T));

                ECFieldElement Z3 = Two(Y1);
                if (!Z1IsOne)
                {
                    Z3 = Z3.Multiply(Z1);
                }

                // Alternative calculation of Z3 using fast square
                //ECFieldElement Z3 = DoubleProductFromSquares(Y1, Z1, Y1Squared, Z1Squared);

                return new FpPoint(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }

            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                return TwiceJacobianModified(true);
            }

            default:
            {
                throw new InvalidOperationException("unsupported coordinate system");
            }
            }
        }

        /// <inheritdoc/>
        public override ECPoint TwicePlus(ECPoint b)
        {
            if (this == b)
                return ThreeTimes();
            if (IsInfinity)
                return b;
            if (b.IsInfinity)
                return Twice();

            ECFieldElement Y1 = RawYCoord;
            if (Y1.IsZero)
                return b;

            ECCurve curve = Curve;
            int coord = curve.CoordinateSystem;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement X1 = RawXCoord;
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
                    return Curve.Infinity;

                ECFieldElement D = d.Multiply(dx);
                ECFieldElement I = D.Invert();
                ECFieldElement L1 = d.Multiply(I).Multiply(dy);
                ECFieldElement L2 = Two(Y1).Multiply(X).Multiply(dx).Multiply(I).Subtract(L1);
                ECFieldElement X4 = (L2.Subtract(L1)).Multiply(L1.Add(L2)).Add(X2);
                ECFieldElement Y4 = (X1.Subtract(X4)).Multiply(L2).Subtract(Y1);

                return new FpPoint(Curve, X4, Y4);
            }
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                return TwiceJacobianModified(false).Add(b);
            }
            default:
            {
                return Twice().Add(b);
            }
            }
        }

        /// <inheritdoc/>
        public override ECPoint ThreeTimes()
        {
            if (IsInfinity)
                return this;

            ECFieldElement Y1 = RawYCoord;
            if (Y1.IsZero)
                return this;

            ECCurve curve = Curve;
            int coord = curve.CoordinateSystem;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement X1 = RawXCoord;

                ECFieldElement _2Y1 = Two(Y1);
                ECFieldElement X = _2Y1.Square();
                ECFieldElement Z = Three(X1.Square()).Add(Curve.A);
                ECFieldElement Y = Z.Square();

                ECFieldElement d = Three(X1).Multiply(X).Subtract(Y);
                if (d.IsZero)
                    return Curve.Infinity;

                ECFieldElement D = d.Multiply(_2Y1);
                ECFieldElement I = D.Invert();
                ECFieldElement L1 = d.Multiply(I).Multiply(Z);
                ECFieldElement L2 = X.Square().Multiply(I).Subtract(L1);

                ECFieldElement X4 = (L2.Subtract(L1)).Multiply(L1.Add(L2)).Add(X1);
                ECFieldElement Y4 = (X1.Subtract(X4)).Multiply(L2).Subtract(Y1);
                return new FpPoint(Curve, X4, Y4);
            }
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                return TwiceJacobianModified(false).Add(this);
            }
            default:
            {
                // NOTE: Be careful about recursions between TwicePlus and ThreeTimes
                return Twice().Add(this);
            }
            }
        }

        /// <inheritdoc/>
        public override ECPoint TimesPow2(int e)
        {
            if (e < 0)
                throw new ArgumentException("cannot be negative", "e");
            if (e == 0 || IsInfinity)
                return this;
            if (e == 1)
                return Twice();

            ECCurve curve = Curve;

            ECFieldElement Y1 = RawYCoord;
            if (Y1.IsZero)
                return curve.Infinity;

            int coord = curve.CoordinateSystem;

            ECFieldElement W1 = curve.A;
            ECFieldElement X1 = RawXCoord;
            ECFieldElement Z1 = RawZCoords.Length < 1 ? curve.FromBigInteger(BigInteger.One) : RawZCoords[0];

            if (!Z1.IsOne)
            {
                switch (coord)
                {
                case ECCurve.COORD_HOMOGENEOUS:
                    ECFieldElement Z1Sq = Z1.Square();
                    X1 = X1.Multiply(Z1);
                    Y1 = Y1.Multiply(Z1Sq);
                    W1 = CalculateJacobianModifiedW(Z1, Z1Sq);
                    break;
                case ECCurve.COORD_JACOBIAN:
                    W1 = CalculateJacobianModifiedW(Z1, null);
                    break;
                case ECCurve.COORD_JACOBIAN_MODIFIED:
                    W1 = GetJacobianModifiedW();
                    break;
                }
            }

            for (int i = 0; i < e; ++i)
            {
                if (Y1.IsZero)
                    return curve.Infinity;

                ECFieldElement X1Squared = X1.Square();
                ECFieldElement M = Three(X1Squared);
                ECFieldElement _2Y1 = Two(Y1);
                ECFieldElement _2Y1Squared = _2Y1.Multiply(Y1);
                ECFieldElement S = Two(X1.Multiply(_2Y1Squared));
                ECFieldElement _4T = _2Y1Squared.Square();
                ECFieldElement _8T = Two(_4T);

                if (!W1.IsZero)
                {
                    M = M.Add(W1);
                    W1 = Two(_8T.Multiply(W1));
                }

                X1 = M.Square().Subtract(Two(S));
                Y1 = M.Multiply(S.Subtract(X1)).Subtract(_8T);
                Z1 = Z1.IsOne ? _2Y1 : _2Y1.Multiply(Z1);
            }

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
                ECFieldElement zInv = Z1.Invert(), zInv2 = zInv.Square(), zInv3 = zInv2.Multiply(zInv);
                return new FpPoint(curve, X1.Multiply(zInv2), Y1.Multiply(zInv3));
            case ECCurve.COORD_HOMOGENEOUS:
                X1 = X1.Multiply(Z1);
                Z1 = Z1.Multiply(Z1.Square());
                return new FpPoint(curve, X1, Y1, new ECFieldElement[]{ Z1 });
            case ECCurve.COORD_JACOBIAN:
                return new FpPoint(curve, X1, Y1, new ECFieldElement[]{ Z1 });
            case ECCurve.COORD_JACOBIAN_MODIFIED:
                return new FpPoint(curve, X1, Y1, new ECFieldElement[]{ Z1, W1 });
            default:
                throw new InvalidOperationException("unsupported coordinate system");
            }
        }

        /// <summary>Return the double of a field element.</summary>
        /// <param name="x">The element.</param>
        /// <returns>The result.</returns>
        protected virtual ECFieldElement Two(ECFieldElement x) => x.Add(x);

        /// <summary>Return three times a field element.</summary>
        /// <param name="x">The element.</param>
        /// <returns>The result.</returns>
        protected virtual ECFieldElement Three(ECFieldElement x) => Two(x).Add(x);

        /// <summary>Return four times a field element.</summary>
        /// <param name="x">The element.</param>
        /// <returns>The result.</returns>
        protected virtual ECFieldElement Four(ECFieldElement x) => Two(Two(x));

        /// <summary>Return eight times a field element.</summary>
        /// <param name="x">The element.</param>
        /// <returns>The result.</returns>
        protected virtual ECFieldElement Eight(ECFieldElement x) => Four(Two(x));

        /// <summary>Calculate 2*a*b from a, b and their squares.</summary>
        /// <param name="a">The first value.</param>
        /// <param name="b">The second value.</param>
        /// <param name="aSquared">The square of the first value.</param>
        /// <param name="bSquared">The square of the second value.</param>
        /// <returns>The result.</returns>
        protected virtual ECFieldElement DoubleProductFromSquares(ECFieldElement a, ECFieldElement b,
            ECFieldElement aSquared, ECFieldElement bSquared)
        {
            /*
             * NOTE: If squaring in the field is faster than multiplication, then this is a quicker
             * way to calculate 2.A.B, if A^2 and B^2 are already known.
             */
            return a.Add(b).Square().Subtract(aSquared).Subtract(bSquared);
        }

        /// <inheritdoc/>
        public override ECPoint Negate()
        {
            if (IsInfinity)
                return this;

            ECCurve curve = Curve;
            int coord = curve.CoordinateSystem;

            if (ECCurve.COORD_AFFINE != coord)
                return new FpPoint(curve, RawXCoord, RawYCoord.Negate(), RawZCoords);

            return new FpPoint(curve, RawXCoord, RawYCoord.Negate());
        }

        /// <summary>Calculate the extra coordinate W = a*Z^4 used by modified Jacobian coordinates.</summary>
        /// <param name="Z">The Z coordinate.</param>
        /// <param name="ZSquared">The square of the Z coordinate, or null.</param>
        /// <returns>The W coordinate.</returns>
        protected virtual ECFieldElement CalculateJacobianModifiedW(ECFieldElement Z, ECFieldElement ZSquared)
        {
            ECFieldElement a4 = Curve.A;
            if (a4.IsZero || Z.IsOne)
                return a4;

            if (ZSquared == null)
            {
                ZSquared = Z.Square();
            }

            ECFieldElement W = ZSquared.Square();
            ECFieldElement a4Neg = a4.Negate();
            if (a4Neg.BitLength < a4.BitLength)
            {
                W = W.Multiply(a4Neg).Negate();
            }
            else
            {
                W = W.Multiply(a4);
            }
            return W;
        }

        /// <summary>Return the jacobian modified w.</summary>
        protected virtual ECFieldElement GetJacobianModifiedW()
        {
            ECFieldElement[] ZZ = RawZCoords;
            ECFieldElement W = ZZ[1];
            if (W == null)
            {
                // NOTE: Rarely, TwicePlus will result in the need for a lazy W1 calculation here
                ZZ[1] = W = CalculateJacobianModifiedW(ZZ[0], null);
            }
            return W;
        }

        /// <summary>Double this point in modified Jacobian coordinates.</summary>
        /// <param name="calculateW">true to calculate the W coordinate of the result.</param>
        /// <returns>The doubled point.</returns>
        protected virtual FpPoint TwiceJacobianModified(bool calculateW)
        {
            ECFieldElement X1 = RawXCoord, Y1 = RawYCoord, Z1 = RawZCoords[0], W1 = GetJacobianModifiedW();

            ECFieldElement X1Squared = X1.Square();
            ECFieldElement M = Three(X1Squared).Add(W1);
            ECFieldElement _2Y1 = Two(Y1);
            ECFieldElement _2Y1Squared = _2Y1.Multiply(Y1);
            ECFieldElement S = Two(X1.Multiply(_2Y1Squared));
            ECFieldElement X3 = M.Square().Subtract(Two(S));
            ECFieldElement _4T = _2Y1Squared.Square();
            ECFieldElement _8T = Two(_4T);
            ECFieldElement Y3 = M.Multiply(S.Subtract(X3)).Subtract(_8T);
            ECFieldElement W3 = calculateW ? Two(_8T.Multiply(W1)) : null;
            ECFieldElement Z3 = Z1.IsOne ? _2Y1 : _2Y1.Multiply(Z1);

            return new FpPoint(Curve, X3, Y3, new ECFieldElement[]{ Z3, W3 });
        }
    }

    /// <summary>Base class for points on curves over a binary field.</summary>
    public abstract class AbstractF2mPoint
        : ECPointBase
    {
        /// <summary>Create a new <see cref="AbstractF2mPoint"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="x">The first operand.</param>
        /// <param name="y">The second operand.</param>
        protected AbstractF2mPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : base(curve, x, y)
        {
        }

        /// <summary>Create a new <see cref="AbstractF2mPoint"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="x">The first operand.</param>
        /// <param name="y">The second operand.</param>
        /// <param name="zs">The zs.</param>
        protected AbstractF2mPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
            : base(curve, x, y, zs)
        {
        }

        /// <inheritdoc/>
        protected override bool SatisfiesCurveEquation()
        {
            ECCurve curve = Curve;
            ECFieldElement X = RawXCoord, Y = RawYCoord, A = curve.A, B = curve.B;
            ECFieldElement lhs, rhs;

            int coord = curve.CoordinateSystem;
            if (coord == ECCurve.COORD_LAMBDA_PROJECTIVE)
            {
                ECFieldElement Z = RawZCoords[0];
                bool ZIsOne = Z.IsOne;

                if (X.IsZero)
                {
                    // NOTE: For x == 0, we expect the affine-y instead of the lambda-y
                    lhs = Y.Square();
                    rhs = B;
                    if (!ZIsOne)
                    {
                        ECFieldElement Z2 = Z.Square();
                        rhs = rhs.Multiply(Z2);
                    }
                }
                else
                {
                    ECFieldElement L = Y, X2 = X.Square();
                    if (ZIsOne)
                    {
                        lhs = L.Square().Add(L).Add(A);
                        rhs = X2.Square().Add(B);
                    }
                    else
                    {
                        ECFieldElement Z2 = Z.Square(), Z4 = Z2.Square();
                        lhs = L.Add(Z).MultiplyPlusProduct(L, A, Z2);
                        // TODO If sqrt(b) is precomputed this can be simplified to a single square
                        rhs = X2.SquarePlusProduct(B, Z4);
                    }
                    lhs = lhs.Multiply(X2);
                }
            }
            else
            {
                lhs = Y.Add(X).Multiply(Y);

                switch (coord)
                {
                case ECCurve.COORD_AFFINE:
                    break;
                case ECCurve.COORD_HOMOGENEOUS:
                {
                    ECFieldElement Z = RawZCoords[0];
                    if (!Z.IsOne)
                    {
                        ECFieldElement Z2 = Z.Square(), Z3 = Z.Multiply(Z2);
                        lhs = lhs.Multiply(Z);
                        A = A.Multiply(Z);
                        B = B.Multiply(Z3);
                    }
                    break;
                }
                default:
                    throw new InvalidOperationException("unsupported coordinate system");
                }

                rhs = X.Add(A).Multiply(X.Square()).Add(B);
            }

            return lhs.Equals(rhs);
        }

        /// <inheritdoc/>
        protected override bool SatisfiesOrder()
        {
            ECCurve curve = Curve;
            BigInteger cofactor = curve.Cofactor;
            if (BigInteger.Two.Equals(cofactor))
            {
                /*
                 * Check that 0 == Tr(X + A); then there exists a solution to L^2 + L = X + A, and
                 * so a halving is possible, so this point is the double of another.
                 *
                 * Note: Tr(A) == 1 for cofactor 2 curves.
                 */
                ECPoint N = Normalize();
                ECFieldElement X = N.AffineXCoord;
                return 0 != ((AbstractF2mFieldElement)X).Trace();
            }
            if (BigInteger.Four.Equals(cofactor))
            {
                /*
                 * Solve L^2 + L = X + A to find the half of this point, if it exists (fail if not).
                 *
                 * Note: Tr(A) == 0 for cofactor 4 curves.
                 */
                ECPoint N = Normalize();
                ECFieldElement X = N.AffineXCoord;
                ECFieldElement L = ((AbstractF2mCurve)curve).SolveQuadraticEquation(X.Add(curve.A));
                if (null == L)
                    return false;

                /*
                 * A solution exists, therefore 0 == Tr(X + A) == Tr(X).
                 */
                ECFieldElement Y = N.AffineYCoord;
                ECFieldElement T = X.Multiply(L).Add(Y);

                /*
                 * Either T or (T + X) is the square of a half-point's x coordinate (hx). In either
                 * case, the half-point can be halved again when 0 == Tr(hx + A).
                 *
                 * Note: Tr(hx + A) == Tr(hx) == Tr(hx^2) == Tr(T) == Tr(T + X)
                 *
                 * Check that 0 == Tr(T); then there exists a solution to L^2 + L = hx + A, and so a
                 * second halving is possible and this point is four times some other.
                 */
                return 0 == ((AbstractF2mFieldElement)T).Trace();
            }

            return base.SatisfiesOrder();
        }

        /// <inheritdoc/>
        public override ECPoint ScaleX(ECFieldElement scale)
        {
            if (IsInfinity)
                return this;

            switch (CurveCoordinateSystem)
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                // Y is actually Lambda (X + Y/X) here
                ECFieldElement X = RawXCoord, L = RawYCoord;

                ECFieldElement X2 = X.Multiply(scale);
                ECFieldElement L2 = L.Add(X).Divide(scale).Add(X2);

                return Curve.CreateRawPoint(X, L2, RawZCoords);
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // Y is actually Lambda (X + Y/X) here
                ECFieldElement X = RawXCoord, L = RawYCoord, Z = RawZCoords[0];

                // We scale the Z coordinate also, to avoid an inversion
                ECFieldElement X2 = X.Multiply(scale.Square());
                ECFieldElement L2 = L.Add(X).Add(X2);
                ECFieldElement Z2 = Z.Multiply(scale);

                return Curve.CreateRawPoint(X, L2, new ECFieldElement[]{ Z2 });
            }
            default:
            {
                return base.ScaleX(scale);
            }
            }
        }

        /// <inheritdoc/>
        public override ECPoint ScaleXNegateY(ECFieldElement scale) => ScaleX(scale);

        /// <inheritdoc/>
        public override ECPoint ScaleY(ECFieldElement scale)
        {
            if (IsInfinity)
                return this;

            switch (CurveCoordinateSystem)
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                ECFieldElement X = RawXCoord, L = RawYCoord;

                // Y is actually Lambda (X + Y/X) here
                ECFieldElement L2 = L.Add(X).Multiply(scale).Add(X);

                return Curve.CreateRawPoint(X, L2, RawZCoords);
            }
            default:
            {
                return base.ScaleY(scale);
            }
            }
        }

        /// <inheritdoc/>
        public override ECPoint ScaleYNegateX(ECFieldElement scale) => ScaleY(scale);

        /// <inheritdoc/>
        public override ECPoint Subtract(ECPoint b)
        {
            if (b.IsInfinity)
                return this;

            // Add -b
            return Add(b.Negate());
        }

        /// <summary>Apply the Frobenius map to this point (the tau function for Koblitz curves).</summary>
        /// <returns>The result.</returns>
        public virtual AbstractF2mPoint Tau()
        {
            if (IsInfinity)
                return this;

            ECCurve curve = Curve;
            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = RawXCoord;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                ECFieldElement Y1 = RawYCoord;
                return (AbstractF2mPoint)curve.CreateRawPoint(X1.Square(), Y1.Square());
            }
            case ECCurve.COORD_HOMOGENEOUS:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                ECFieldElement Y1 = RawYCoord, Z1 = RawZCoords[0];
                return (AbstractF2mPoint)curve.CreateRawPoint(X1.Square(), Y1.Square(),
                    new ECFieldElement[]{ Z1.Square() });
            }
            default:
            {
                throw new InvalidOperationException("unsupported coordinate system");
            }
            }
        }

        /// <summary>Apply the Frobenius map to this point a number of times.</summary>
        /// <param name="pow">The number of times.</param>
        /// <returns>The result.</returns>
        public virtual AbstractF2mPoint TauPow(int pow)
        {
            if (IsInfinity)
                return this;

            ECCurve curve = Curve;
            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = RawXCoord;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                ECFieldElement Y1 = RawYCoord;
                return (AbstractF2mPoint)curve.CreateRawPoint(X1.SquarePow(pow), Y1.SquarePow(pow));
            }
            case ECCurve.COORD_HOMOGENEOUS:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                ECFieldElement Y1 = RawYCoord, Z1 = RawZCoords[0];
                return (AbstractF2mPoint)curve.CreateRawPoint(X1.SquarePow(pow), Y1.SquarePow(pow),
                    new ECFieldElement[]{ Z1.SquarePow(pow) });
            }
            default:
            {
                throw new InvalidOperationException("unsupported coordinate system");
            }
            }
        }
    }

    /// <summary>Elliptic curve points over F2m.</summary>
    public class F2mPoint
        : AbstractF2mPoint
    {
        internal F2mPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : base(curve, x, y)
        {
            if ((x == null) != (y == null))
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

        internal F2mPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
            : base(curve, x, y, zs)
        {
        }

        /// <inheritdoc/>
        [Obsolete("Will be removed")]
        protected override ECPoint Detach() => new F2mPoint(null, AffineXCoord, AffineYCoord);

        /// <inheritdoc/>
        public override ECFieldElement YCoord
        {
            get
            {
                int coord = CurveCoordinateSystem;

                switch (coord)
                {
                case ECCurve.COORD_LAMBDA_AFFINE:
                case ECCurve.COORD_LAMBDA_PROJECTIVE:
                {
                    ECFieldElement X = RawXCoord, L = RawYCoord;

                    if (IsInfinity || X.IsZero)
                        return L;

                    // Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
                    ECFieldElement Y = L.Add(X).Multiply(X);
                    if (ECCurve.COORD_LAMBDA_PROJECTIVE == coord)
                    {
                        ECFieldElement Z = RawZCoords[0];
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

        /// <inheritdoc/>
        protected internal override bool CompressionYTilde
        {
            get
            {
                ECFieldElement X = RawXCoord;
                if (X.IsZero)
                    return false;

                ECFieldElement Y = RawYCoord;

                switch (CurveCoordinateSystem)
                {
                case ECCurve.COORD_LAMBDA_AFFINE:
                case ECCurve.COORD_LAMBDA_PROJECTIVE:
                {
                    // Y is actually Lambda (X + Y/X) here
                    return Y.TestBitZero() != X.TestBitZero();
                }
                default:
                {
                    return Y.Divide(X).TestBitZero();
                }
                }
            }
        }

        /// <inheritdoc/>
        public override ECPoint Add(ECPoint b)
        {
            if (IsInfinity)
                return b;
            if (b.IsInfinity)
                return this;

            ECCurve curve = Curve;
            int coord = curve.CoordinateSystem;

            ECFieldElement X1 = RawXCoord;
            ECFieldElement X2 = b.RawXCoord;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement Y1 = RawYCoord;
                ECFieldElement Y2 = b.RawYCoord;

                ECFieldElement dx = X1.Add(X2), dy = Y1.Add(Y2);
                if (dx.IsZero)
                {
                    if (dy.IsZero)
                        return Twice();

                    return curve.Infinity;
                }

                ECFieldElement L = dy.Divide(dx);

                ECFieldElement X3 = L.Square().Add(L).Add(dx).Add(curve.A);
                ECFieldElement Y3 = L.Multiply(X1.Add(X3)).Add(X3).Add(Y1);

                return new F2mPoint(curve, X3, Y3);
            }
            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Y1 = RawYCoord, Z1 = RawZCoords[0];
                ECFieldElement Y2 = b.RawYCoord, Z2 = b.RawZCoords[0];

                bool Z1IsOne = Z1.IsOne;
                ECFieldElement U1 = Y2, V1 = X2;
                if (!Z1IsOne)
                {
                    U1 = U1.Multiply(Z1);
                    V1 = V1.Multiply(Z1);
                }

                bool Z2IsOne = Z2.IsOne;
                ECFieldElement U2 = Y1, V2 = X1;
                if (!Z2IsOne)
                {
                    U2 = U2.Multiply(Z2);
                    V2 = V2.Multiply(Z2);
                }

                ECFieldElement U = U1.Add(U2);
                ECFieldElement V = V1.Add(V2);

                if (V.IsZero)
                {
                    if (U.IsZero)
                    {
                        return Twice();
                    }

                    return curve.Infinity;
                }

                ECFieldElement VSq = V.Square();
                ECFieldElement VCu = VSq.Multiply(V);
                ECFieldElement W = Z1IsOne ? Z2 : Z2IsOne ? Z1 : Z1.Multiply(Z2);
                ECFieldElement uv = U.Add(V);
                ECFieldElement A = uv.MultiplyPlusProduct(U, VSq, curve.A).Multiply(W).Add(VCu);

                ECFieldElement X3 = V.Multiply(A);
                ECFieldElement VSqZ2 = Z2IsOne ? VSq : VSq.Multiply(Z2);
                ECFieldElement Y3 = U.MultiplyPlusProduct(X1, V, Y1).MultiplyPlusProduct(VSqZ2, uv, A);
                ECFieldElement Z3 = VCu.Multiply(W);

                return new F2mPoint(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                if (X1.IsZero)
                {
                    if (X2.IsZero)
                        return curve.Infinity;

                    return b.Add(this);
                }

                ECFieldElement L1 = RawYCoord, Z1 = RawZCoords[0];
                ECFieldElement L2 = b.RawYCoord, Z2 = b.RawZCoords[0];

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
                        return Twice();

                    return curve.Infinity;
                }

                ECFieldElement X3, L3, Z3;
                if (X2.IsZero)
                {
                    // TODO This can probably be optimized quite a bit
                    ECPoint p = Normalize();
                    X1 = p.RawXCoord;
                    ECFieldElement Y1 = p.YCoord;

                    ECFieldElement Y2 = L2;
                    ECFieldElement L = Y1.Add(Y2).Divide(X1);

                    X3 = L.Square().Add(L).Add(X1).Add(curve.A);
                    if (X3.IsZero)
                        return new F2mPoint(curve, X3, curve.B.Sqrt());

                    ECFieldElement Y3 = L.Multiply(X1.Add(X3)).Add(X3).Add(Y1);
                    L3 = Y3.Divide(X3).Add(X3);
                    Z3 = curve.FromBigInteger(BigInteger.One);
                }
                else
                {
                    B = B.Square();

                    ECFieldElement AU1 = A.Multiply(U1);
                    ECFieldElement AU2 = A.Multiply(U2);

                    X3 = AU1.Multiply(AU2);
                    if (X3.IsZero)
                        return new F2mPoint(curve, X3, curve.B.Sqrt());

                    ECFieldElement ABZ2 = A.Multiply(B);
                    if (!Z2IsOne)
                    {
                        ABZ2 = ABZ2.Multiply(Z2);
                    }

                    L3 = AU2.Add(B).SquarePlusProduct(ABZ2, L1.Add(Z1));

                    Z3 = ABZ2;
                    if (!Z1IsOne)
                    {
                        Z3 = Z3.Multiply(Z1);
                    }
                }

                return new F2mPoint(curve, X3, L3, new ECFieldElement[]{ Z3 });
            }
            default:
            {
                throw new InvalidOperationException("unsupported coordinate system");
            }
            }
        }

        /// <inheritdoc/>
        public override ECPoint Twice()
        {
            if (IsInfinity)
                return this;

            ECCurve curve = Curve;

            ECFieldElement X1 = RawXCoord;
            if (X1.IsZero)
            {
                // A point with X == 0 is its own additive inverse
                return curve.Infinity;
            }

            int coord = curve.CoordinateSystem;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement Y1 = RawYCoord;

                ECFieldElement L1 = Y1.Divide(X1).Add(X1);

                ECFieldElement X3 = L1.Square().Add(L1).Add(curve.A);
                ECFieldElement Y3 = X1.SquarePlusProduct(X3, L1.AddOne());

                return new F2mPoint(curve, X3, Y3);
            }
            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Y1 = RawYCoord, Z1 = RawZCoords[0];

                bool Z1IsOne = Z1.IsOne;
                ECFieldElement X1Z1 = Z1IsOne ? X1 : X1.Multiply(Z1);
                ECFieldElement Y1Z1 = Z1IsOne ? Y1 : Y1.Multiply(Z1);

                ECFieldElement X1Sq = X1.Square();
                ECFieldElement S = X1Sq.Add(Y1Z1);
                ECFieldElement V = X1Z1;
                ECFieldElement vSquared = V.Square();
                ECFieldElement sv = S.Add(V);
                ECFieldElement h = sv.MultiplyPlusProduct(S, vSquared, curve.A);

                ECFieldElement X3 = V.Multiply(h);
                ECFieldElement Y3 = X1Sq.Square().MultiplyPlusProduct(V, h, sv);
                ECFieldElement Z3 = V.Multiply(vSquared);

                return new F2mPoint(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                ECFieldElement L1 = RawYCoord, Z1 = RawZCoords[0];

                bool Z1IsOne = Z1.IsOne;
                ECFieldElement L1Z1 = Z1IsOne ? L1 : L1.Multiply(Z1);
                ECFieldElement Z1Sq = Z1IsOne ? Z1 : Z1.Square();
                ECFieldElement a = curve.A;
                ECFieldElement aZ1Sq = Z1IsOne ? a : a.Multiply(Z1Sq);
                ECFieldElement T = L1.Square().Add(L1Z1).Add(aZ1Sq);
                if (T.IsZero)
                {
                    return new F2mPoint(curve, T, curve.B.Sqrt());
                }

                ECFieldElement X3 = T.Square();
                ECFieldElement Z3 = Z1IsOne ? T : T.Multiply(Z1Sq);

                ECFieldElement b = curve.B;
                ECFieldElement L3;
                if (b.BitLength < (curve.FieldSize >> 1))
                {
                    ECFieldElement t1 = L1.Add(X1).Square();
                    ECFieldElement t2;
                    if (b.IsOne)
                    {
                        t2 = aZ1Sq.Add(Z1Sq).Square();
                    }
                    else
                    {
                        // TODO Can be calculated with one square if we pre-compute sqrt(b)
                        t2 = aZ1Sq.SquarePlusProduct(b, Z1Sq.Square());
                    }
                    L3 = t1.Add(T).Add(Z1Sq).Multiply(t1).Add(t2).Add(X3);
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
                    L3 = X1Z1.SquarePlusProduct(T, L1Z1).Add(X3).Add(Z3);
                }

                return new F2mPoint(curve, X3, L3, new ECFieldElement[]{ Z3 });
            }
            default:
            {
                throw new InvalidOperationException("unsupported coordinate system");
            }
            }
        }

        /// <inheritdoc/>
        public override ECPoint TwicePlus(ECPoint b)
        {
            if (IsInfinity)
                return b;
            if (b.IsInfinity)
                return Twice();

            ECCurve curve = Curve;

            ECFieldElement X1 = RawXCoord;
            if (X1.IsZero)
            {
                // A point with X == 0 is its own additive inverse
                return b;
            }

            int coord = curve.CoordinateSystem;

            switch (coord)
            {
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // NOTE: twicePlus() only optimized for lambda-affine argument
                ECFieldElement X2 = b.RawXCoord, Z2 = b.RawZCoords[0];
                if (X2.IsZero || !Z2.IsOne)
                    return Twice().Add(b);

                ECFieldElement L1 = RawYCoord, Z1 = RawZCoords[0];
                ECFieldElement L2 = b.RawYCoord;

                ECFieldElement X1Sq = X1.Square();
                ECFieldElement L1Sq = L1.Square();
                ECFieldElement Z1Sq = Z1.Square();
                ECFieldElement L1Z1 = L1.Multiply(Z1);

                ECFieldElement T = curve.A.Multiply(Z1Sq).Add(L1Sq).Add(L1Z1);
                ECFieldElement L2plus1 = L2.AddOne();
                ECFieldElement A = curve.A.Add(L2plus1).Multiply(Z1Sq).Add(L1Sq).MultiplyPlusProduct(T, X1Sq, Z1Sq);
                ECFieldElement X2Z1Sq = X2.Multiply(Z1Sq);
                ECFieldElement B = X2Z1Sq.Add(T).Square();

                if (B.IsZero)
                {
                    if (A.IsZero)
                        return b.Twice();

                    return curve.Infinity;
                }

                if (A.IsZero)
                    return new F2mPoint(curve, A, curve.B.Sqrt());

                ECFieldElement X3 = A.Square().Multiply(X2Z1Sq);
                ECFieldElement Z3 = A.Multiply(B).Multiply(Z1Sq);
                ECFieldElement L3 = A.Add(B).Square().MultiplyPlusProduct(T, L2plus1, Z3);

                return new F2mPoint(curve, X3, L3, new ECFieldElement[]{ Z3 });
            }
            default:
            {
                return Twice().Add(b);
            }
            }
        }

        /// <inheritdoc/>
        public override ECPoint Negate()
        {
            if (IsInfinity)
                return this;

            ECFieldElement X = RawXCoord;
            if (X.IsZero)
                return this;

            ECCurve curve = Curve;
            int coord = curve.CoordinateSystem;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement Y = RawYCoord;
                return new F2mPoint(curve, X, Y.Add(X));
            }
            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Y = RawYCoord, Z = RawZCoords[0];
                return new F2mPoint(curve, X, Y.Add(X), new ECFieldElement[]{ Z });
            }
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                ECFieldElement L = RawYCoord;
                return new F2mPoint(curve, X, L.AddOne());
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // L is actually Lambda (X + Y/X) here
                ECFieldElement L = RawYCoord, Z = RawZCoords[0];
                return new F2mPoint(curve, X, L.Add(Z), new ECFieldElement[]{ Z });
            }
            default:
            {
                throw new InvalidOperationException("unsupported coordinate system");
            }
            }
        }
    }
}
