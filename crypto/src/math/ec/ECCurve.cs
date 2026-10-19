using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

using Org.BouncyCastle.Math.BinPoly;
using Org.BouncyCastle.Math.EC.Endo;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Math.Field;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC
{
    /// <remarks>Base class for an elliptic curve.</remarks>
    public abstract class ECCurve
    {
        /// <summary>The <c>COORD_AFFINE</c> constant, with the value <c>0</c>.</summary>
        public const int COORD_AFFINE = 0;
        /// <summary>The <c>COORD_HOMOGENEOUS</c> constant, with the value <c>1</c>.</summary>
        public const int COORD_HOMOGENEOUS = 1;
        /// <summary>The <c>COORD_JACOBIAN</c> constant, with the value <c>2</c>.</summary>
        public const int COORD_JACOBIAN = 2;
        /// <summary>The <c>COORD_JACOBIAN_CHUDNOVSKY</c> constant, with the value <c>3</c>.</summary>
        public const int COORD_JACOBIAN_CHUDNOVSKY = 3;
        /// <summary>The <c>COORD_JACOBIAN_MODIFIED</c> constant, with the value <c>4</c>.</summary>
        public const int COORD_JACOBIAN_MODIFIED = 4;
        /// <summary>The <c>COORD_LAMBDA_AFFINE</c> constant, with the value <c>5</c>.</summary>
        public const int COORD_LAMBDA_AFFINE = 5;
        /// <summary>The <c>COORD_LAMBDA_PROJECTIVE</c> constant, with the value <c>6</c>.</summary>
        public const int COORD_LAMBDA_PROJECTIVE = 6;
        /// <summary>The <c>COORD_SKEWED</c> constant, with the value <c>7</c>.</summary>
        public const int COORD_SKEWED = 7;

        /// <summary>Return the all coordinate systems.</summary>
        public static int[] GetAllCoordinateSystems()
        {
            return new int[]{ COORD_AFFINE, COORD_HOMOGENEOUS, COORD_JACOBIAN, COORD_JACOBIAN_CHUDNOVSKY,
                COORD_JACOBIAN_MODIFIED, COORD_LAMBDA_AFFINE, COORD_LAMBDA_PROJECTIVE, COORD_SKEWED };
        }

        /// <summary>
        /// A configuration for creating a curve with chosen coordinate system, endomorphism and multiplier.
        /// </summary>
        public class Config
        {
            private readonly ECCurve m_outer;
            private int m_coord;
            private ECEndomorphism m_endomorphism;
            private ECMultiplier m_multiplier;

            internal Config(ECCurve outer, int coord, ECEndomorphism endomorphism, ECMultiplier multiplier)
            {
                m_outer = outer;
                m_coord = coord;
                m_endomorphism = endomorphism;
                m_multiplier = multiplier;
            }

            /// <summary>Set the coordinate system.</summary>
            /// <param name="coord">The coordinate system.</param>
            /// <returns>This configuration.</returns>
            public Config SetCoordinateSystem(int coord)
            {
                m_coord = coord;
                return this;
            }

            /// <summary>Set the endomorphism.</summary>
            /// <param name="endomorphism">The endomorphism.</param>
            /// <returns>This configuration.</returns>
            public Config SetEndomorphism(ECEndomorphism endomorphism)
            {
                m_endomorphism = endomorphism;
                return this;
            }

            /// <summary>Set the multiplier.</summary>
            /// <param name="multiplier">The multiplier.</param>
            /// <returns>This configuration.</returns>
            public Config SetMultiplier(ECMultiplier multiplier)
            {
                m_multiplier = multiplier;
                return this;
            }

            /// <summary>Create the curve with the chosen configuration.</summary>
            /// <returns>The curve.</returns>
            public ECCurve Create()
            {
                if (!m_outer.SupportsCoordinateSystem(m_coord))
                    throw new InvalidOperationException("unsupported coordinate system");

                ECCurve c = m_outer.CloneCurve();
                if (c == m_outer)
                    throw new InvalidOperationException("implementation returned current curve");

                c.m_coord = m_coord;
                c.m_endomorphism = m_endomorphism;
                c.m_multiplier = m_multiplier;

                return c;
            }
        }

        /// <summary>The field.</summary>
        protected readonly IFiniteField m_field;
        /// <summary>The b.</summary>
        protected ECFieldElement m_a, m_b;
        /// <summary>The cofactor.</summary>
        protected BigInteger m_order, m_cofactor;

        /// <summary>The coord.</summary>
        protected int m_coord = COORD_AFFINE;
        /// <summary>The endomorphism.</summary>
        protected ECEndomorphism m_endomorphism = null;
        /// <summary>The multiplier.</summary>
        protected ECMultiplier m_multiplier = null;

        private IDictionary<string, PreCompInfo> m_preCompTable = null;

        /// <summary>Create a new <see cref="ECCurve"/>.</summary>
        /// <param name="field">The field.</param>
        protected ECCurve(IFiniteField field)
        {
            m_field = field;
        }

        /// <summary>Gets the field size.</summary>
        public abstract int FieldSize { get; }
        /// <summary>Create a field element of this curve from a value.</summary>
        /// <param name="x">The value.</param>
        /// <returns>The field element.</returns>
        public abstract ECFieldElement FromBigInteger(BigInteger x);
        /// <summary>Determine whether a value is a valid field element of this curve.</summary>
        /// <param name="x">The value.</param>
        /// <returns>true if the value is valid, false otherwise.</returns>
        public abstract bool IsValidFieldElement(BigInteger x);

        /// <summary>Generate a random field element.</summary>
        /// <param name="r">The source of randomness.</param>
        /// <returns>The field element.</returns>
        public abstract ECFieldElement RandomFieldElement(SecureRandom r);

        /// <summary>Generate a random non-zero field element.</summary>
        /// <param name="r">The source of randomness.</param>
        /// <returns>The field element.</returns>
        public abstract ECFieldElement RandomFieldElementMult(SecureRandom r);

        /// <summary>Start configuring a copy of this curve.</summary>
        /// <returns>A configuration for the new curve.</returns>
        public virtual Config Configure() => new Config(this, m_coord, m_endomorphism, m_multiplier);

        /// <summary>Gets the field element encoding length.</summary>
        public virtual int FieldElementEncodingLength => (FieldSize + 7) / 8;

        /// <summary>Get the length in bytes of the encoding of an affine point.</summary>
        /// <param name="compressed">true for the compressed encoding, false for the uncompressed encoding.</param>
        /// <returns>The length in bytes.</returns>
        public virtual int GetAffinePointEncodingLength(bool compressed)
        {
            int fieldLength = FieldElementEncodingLength;
            return compressed
                ?  1 + fieldLength
                :  1 + fieldLength * 2;
        }

        /// <summary>Create a point from affine coordinates and check that it is valid.</summary>
        /// <param name="x">The affine x-coordinate.</param>
        /// <param name="y">The affine y-coordinate.</param>
        /// <returns>The point.</returns>
        /// <exception cref="ArgumentException">The point is not valid.</exception>
        public virtual ECPoint ValidatePoint(BigInteger x, BigInteger y)
        {
            ECPoint p = CreatePoint(x, y);
            if (!p.IsValid())
                throw new ArgumentException("Invalid point coordinates");

            return p;
        }

        /// <summary>Create a point from affine coordinates.</summary>
        /// <param name="x">The affine x-coordinate.</param>
        /// <param name="y">The affine y-coordinate.</param>
        /// <returns>The point.</returns>
        public virtual ECPoint CreatePoint(BigInteger x, BigInteger y) =>
            CreateRawPoint(FromBigInteger(x), FromBigInteger(y));

        /// <summary>Create a copy of this curve.</summary>
        /// <returns>The copy.</returns>
        protected abstract ECCurve CloneCurve();

        /// <summary>Create a point from field elements, without validation.</summary>
        /// <param name="x">The x-coordinate.</param>
        /// <param name="y">The y-coordinate.</param>
        /// <returns>The point.</returns>
        protected internal abstract ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y);

        /// <summary>Create a point from field elements, without validation.</summary>
        /// <param name="x">The x-coordinate.</param>
        /// <param name="y">The y-coordinate.</param>
        /// <param name="zs">The additional coordinates.</param>
        /// <returns>The point.</returns>
        protected internal abstract ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs);

        /// <summary>Create the multiplier used by default for this curve.</summary>
        /// <returns>The multiplier.</returns>
        protected virtual ECMultiplier CreateDefaultMultiplier()
        {
            if (m_endomorphism is GlvEndomorphism glvEndomorphism)
                return new GlvMultiplier(this, glvEndomorphism);

            return new WNafL2RMultiplier();
        }

        /// <summary>Determine whether a coordinate system is supported by this curve.</summary>
        /// <param name="coord">The coordinate system.</param>
        /// <returns>true if the coordinate system is supported, false otherwise.</returns>
        public virtual bool SupportsCoordinateSystem(int coord) => coord == COORD_AFFINE;

        /// <summary>Get the precomputation data stored with a point under the given name.</summary>
        /// <param name="point">The point.</param>
        /// <param name="name">The name of the precomputation.</param>
        /// <returns>The precomputation data, or null if there is none.</returns>
        public virtual PreCompInfo GetPreCompInfo(ECPoint point, string name)
        {
            CheckPoint(point);

            IDictionary<string, PreCompInfo> table;
            lock (point)
            {
                table = point.m_preCompTable;
            }

            if (null == table)
                return null;

            lock (table)
            {
                return table.TryGetValue(name, out var preCompInfo) ? preCompInfo : null;
            }
        }

        internal virtual PreCompInfo Precompute(string name, IPreCompCallback callback)
        {
            IDictionary<string, PreCompInfo> table;
            lock (this)
            {
                table = m_preCompTable;
                if (null == table)
                {
                    m_preCompTable = table = new Dictionary<string, PreCompInfo>();
                }
            }

            lock (table)
            {
                PreCompInfo existing = table.TryGetValue(name, out var preCompInfo) ? preCompInfo : null;
                PreCompInfo result = callback.Precompute(existing);

                if (result != existing)
                {
                    table[name] = result;
                }

                return result;
            }
        }

        /// <summary>
        /// Compute a <see cref="PreCompInfo"/> for a point on this curve, under a given name. Used by
        /// <see cref="ECMultiplier"/>s to save the precomputation for this <see cref="ECPoint"/> for use by subsequent
        /// multiplication.
        /// </summary>
        /// <param name="point">The <see cref="ECPoint"/> to store precomputations for.</param>
        /// <param name="name">A <see cref="string"/> used to index precomputations of different types.</param>
        /// <param name="callback">Called to calculate the <see cref="PreCompInfo"/>.</param>
        public virtual PreCompInfo Precompute(ECPoint point, string name, IPreCompCallback callback)
        {
            CheckPoint(point);

            IDictionary<string, PreCompInfo> table;
            lock (point)
            {
                table = point.m_preCompTable;
                if (null == table)
                {
                    point.m_preCompTable = table = new Dictionary<string, PreCompInfo>();
                }
            }

            lock (table)
            {
                PreCompInfo existing = table.TryGetValue(name, out var preCompInfo) ? preCompInfo : null;
                PreCompInfo result = callback.Precompute(existing);

                if (result != existing)
                {
                    table[name] = result;
                }

                return result;
            }
        }

        /// <summary>Import a point from another curve into this one.</summary>
        /// <param name="p">The point.</param>
        /// <returns>The point on this curve.</returns>
        public virtual ECPoint ImportPoint(ECPoint p)
        {
            if (this == p.Curve)
                return p;

            if (p.IsInfinity)
                return Infinity;

            // TODO Default behaviour could be improved if the two curves have the same coordinate system by copying any Z coordinates.
            p = p.Normalize();

            return CreatePoint(p.XCoord.ToBigInteger(), p.YCoord.ToBigInteger());
        }

        /// <summary>
        /// Normalization ensures that any projective coordinate is 1, and therefore that the x, y coordinates reflect
        /// those of the equivalent point in an affine coordinate system.
        /// </summary>
        /// <remarks>
        /// Where more than one point is to be normalized, this method will generally be more efficient than normalizing
        /// each point separately.
        /// </remarks>
        /// <param name="points">
        /// An array of points that will be updated in place with their normalized versions, where necessary.
        /// </param>
        public virtual void NormalizeAll(ECPoint[] points) => NormalizeAll(points, 0, points.Length, null);

        /// <summary>
        /// Normalization ensures that any projective coordinate is 1, and therefore that the x, y coordinates reflect
        /// those of the equivalent point in an affine coordinate system.
        /// </summary>
        /// <remarks>
        /// Where more than one point is to be normalized, this method will generally be more efficient than normalizing
        /// each point separately.
        /// <para>
        /// An (optional) z-scaling factor can be applied; effectively each z coordinate is scaled by this value prior
        /// to normalization(but only one actual multiplication is needed).
        /// </para>
        /// </remarks>
        /// <param name="points">
        /// An array of points; within the given range points will be updated in place with their normalized versions,
        /// where necessary.
        /// </param>
        /// <param name="off">The start of the range of points to normalize.</param>
        /// <param name="len">The length of the range of points to normalize.</param>
        /// <param name="iso">The (optional) z-scaling factor - can be <c>null</c>.</param>
        public virtual void NormalizeAll(ECPoint[] points, int off, int len, ECFieldElement iso)
        {
            CheckPoints(points, off, len);

            switch (CoordinateSystem)
            {
            case ECCurve.COORD_AFFINE:
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                if (iso != null)
                    throw new ArgumentException("not valid for affine coordinates", nameof(iso));

                return;
            }
            }

            /*
             * Figure out which of the points actually need to be normalized
             */
            ECFieldElement[] zs = new ECFieldElement[len];

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<int> indices = len <= 256
                ? stackalloc int[len]
                : new int[len];
#else
            int[] indices = new int[len];
#endif

            int count = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                if (null != p && (iso != null || !p.IsNormalized()))
                {
                    zs[count] = p.GetZCoord(0);
                    indices[count++] = off + i;
                }
            }

            if (count == 0)
                return;

            ECAlgorithms.MontgomeryTrick(zs, 0, count, iso);

            for (int j = 0; j < count; ++j)
            {
                int index = indices[j];
                points[index] = points[index].Normalize(zs[j]);
            }
        }

        /// <summary>Gets the infinity.</summary>
        public abstract ECPoint Infinity { get; }

        /// <summary>Gets the field.</summary>
        public virtual IFiniteField Field => m_field;
        /// <summary>Gets the a.</summary>
        public virtual ECFieldElement A => m_a;

        /// <summary>Gets the b.</summary>
        public virtual ECFieldElement B => m_b;

        /// <summary>Gets the order.</summary>
        public virtual BigInteger Order => m_order;

        /// <summary>Gets the cofactor.</summary>
        public virtual BigInteger Cofactor => m_cofactor;

        /// <summary>Gets the coordinate system.</summary>
        public virtual int CoordinateSystem => m_coord;

        /// <summary>
        /// Create a cache-safe lookup table for the specified range of points. All the points MUST belong to this
        /// <see cref="ECCurve"/> instance, and MUST already be normalized.
        /// </summary>
        public virtual ECLookupTable CreateCacheSafeLookupTable(ECPoint[] points, int off, int len)
        {
            int FE_BYTES = FieldElementEncodingLength;
            byte[] table = new byte[len * FE_BYTES * 2];
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                p.RawXCoord.EncodeTo(table, pos);       pos += FE_BYTES;
                p.RawYCoord.EncodeTo(table, pos);       pos += FE_BYTES;
            }
            return new DefaultLookupTable(this, table, len);
        }

        /// <summary>Check that a point belongs to this curve.</summary>
        /// <param name="point">The point.</param>
        /// <exception cref="ArgumentException">The point belongs to another curve.</exception>
        protected virtual void CheckPoint(ECPoint point)
        {
            if (null == point || (this != point.Curve))
                throw new ArgumentException("must be non-null and on this curve", nameof(point));
        }

        /// <summary>Check that points belong to this curve.</summary>
        /// <param name="points">The points.</param>
        /// <exception cref="ArgumentException">A point belongs to another curve.</exception>
        protected virtual void CheckPoints(ECPoint[] points) => CheckPoints(points, 0, points.Length);

        /// <summary>Check that points belong to this curve.</summary>
        /// <param name="points">The points.</param>
        /// <param name="off">The offset of the range to check.</param>
        /// <param name="len">The length of the range.</param>
        /// <exception cref="ArgumentException">A point belongs to another curve.</exception>
        protected virtual void CheckPoints(ECPoint[] points, int off, int len)
        {
            Arrays.ValidateSegment(points, off, len);

            for (int i = 0; i < len; ++i)
            {
                ECPoint point = points[off + i];
                if (null != point && this != point.Curve)
                    throw new ArgumentException("entries must be null or on this curve", nameof(points));
            }
        }

        /// <summary>Determine whether this curve is equal to another.</summary>
        /// <param name="other">The curve to compare with.</param>
        /// <returns>true if the curves are equal, false otherwise.</returns>
        public virtual bool Equals(ECCurve other)
        {
            if (this == other)
                return true;

            return other != null
                && Field.Equals(other.Field)
                && A.ToBigInteger().Equals(other.A.ToBigInteger())
                && B.ToBigInteger().Equals(other.B.ToBigInteger());
        }

        /// <inheritdoc/>
        public override bool Equals(object obj) => Equals(obj as ECCurve);

        /// <inheritdoc/>
        public override int GetHashCode()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return HashCode.Combine(Field, A.ToBigInteger(), B.ToBigInteger());
#else
            return Field.GetHashCode()
                ^ Integers.RotateLeft(A.ToBigInteger().GetHashCode(), 8)
                ^ Integers.RotateLeft(B.ToBigInteger().GetHashCode(), 16);
#endif
        }

        /// <summary>Decompress a point from its x-coordinate and the sign of its y-coordinate.</summary>
        /// <param name="yTilde">The least significant bit of the y-coordinate.</param>
        /// <param name="X1">The x-coordinate.</param>
        /// <returns>The point.</returns>
        protected abstract ECPoint DecompressPoint(int yTilde, BigInteger X1);

        /// <summary>Return the endomorphism.</summary>
        public virtual ECEndomorphism GetEndomorphism() => m_endomorphism;

        /// <summary>Sets the default <see cref="ECMultiplier"/>, unless already set.</summary>
        /// <remarks>We avoid locking for performance reasons, so there is no uniqueness guarantee.</remarks>
        public virtual ECMultiplier GetMultiplier()
        {
            if (m_multiplier == null)
            {
                m_multiplier = CreateDefaultMultiplier();
            }
            return m_multiplier;
        }

        /// <summary>Decode a point from its encoding.</summary>
        /// <param name="encoded">The encoding.</param>
        /// <returns>The point.</returns>
        /// <exception cref="ArgumentException">The encoding is not valid.</exception>
        public virtual ECPoint DecodePoint(byte[] encoded)
        {
            if (encoded == null)
                throw new ArgumentNullException(nameof(encoded));

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DecodePoint(encoded.AsSpan());
#else
            if (encoded.Length < 1)
                throw new ArgumentException("Invalid point encoding: empty", nameof(encoded));

            ECPoint p;
            int expectedLength = FieldElementEncodingLength;

            byte type = encoded[0];
            switch (type)
            {
            case 0x00: // infinity
            {
                if (encoded.Length != 1)
                    throw new ArgumentException("Incorrect length for infinity encoding", nameof(encoded));

                p = Infinity;
                break;
            }

            case 0x02: // compressed
            case 0x03: // compressed
            {
                if (encoded.Length != (expectedLength + 1))
                    throw new ArgumentException("Incorrect length for compressed encoding", nameof(encoded));

                int yTilde = type & 1;
                BigInteger X = new BigInteger(1, encoded, 1, expectedLength);

                p = DecompressPoint(yTilde, X);
                if (!p.ImplIsValid(true, true))
                    throw new ArgumentException("Invalid point", nameof(encoded));

                break;
            }

            case 0x04: // uncompressed
            {
                if (encoded.Length != (2 * expectedLength + 1))
                    throw new ArgumentException("Incorrect length for uncompressed encoding", nameof(encoded));

                BigInteger X = new BigInteger(1, encoded, 1, expectedLength);
                BigInteger Y = new BigInteger(1, encoded, 1 + expectedLength, expectedLength);

                p = ValidatePoint(X, Y);
                break;
            }

            case 0x06: // hybrid
            case 0x07: // hybrid
            {
                if (encoded.Length != (2 * expectedLength + 1))
                    throw new ArgumentException("Incorrect length for hybrid encoding", nameof(encoded));

                BigInteger X = new BigInteger(1, encoded, 1, expectedLength);
                BigInteger Y = new BigInteger(1, encoded, 1 + expectedLength, expectedLength);

                if (Y.TestBit(0) != (type == 0x07))
                    throw new ArgumentException("Inconsistent Y coordinate in hybrid encoding", nameof(encoded));

                p = ValidatePoint(X, Y);
                break;
            }

            default:
                throw new FormatException($"Invalid point encoding type: 0x{type:X2}");
            }

            if (type != 0x00 && p.IsInfinity)
                throw new ArgumentException("Invalid infinity encoding", nameof(encoded));

            return p;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Decode a point from its encoding.</summary>
        /// <param name="encoded">The encoding.</param>
        /// <returns>The point.</returns>
        /// <exception cref="ArgumentException">The encoding is not valid.</exception>
        public virtual ECPoint DecodePoint(ReadOnlySpan<byte> encoded)
        {
            if (encoded.Length < 1)
                throw new ArgumentException("Invalid point encoding: empty", nameof(encoded));

            ECPoint p;
            int expectedLength = FieldElementEncodingLength;

            byte type = encoded[0];
            switch (type)
            {
            case 0x00: // infinity
            {
                if (encoded.Length != 1)
                    throw new ArgumentException("Incorrect length for infinity encoding", nameof(encoded));

                p = Infinity;
                break;
            }

            case 0x02: // compressed
            case 0x03: // compressed
            {
                if (encoded.Length != (expectedLength + 1))
                    throw new ArgumentException("Incorrect length for compressed encoding", nameof(encoded));

                int yTilde = type & 1;
                BigInteger X = new BigInteger(1, encoded[1..]);

                p = DecompressPoint(yTilde, X);
                if (!p.ImplIsValid(true, true))
                    throw new ArgumentException("Invalid point", nameof(encoded));

                break;
            }

            case 0x04: // uncompressed
            {
                if (encoded.Length != (2 * expectedLength + 1))
                    throw new ArgumentException("Incorrect length for uncompressed encoding", nameof(encoded));

                BigInteger X = new BigInteger(1, encoded[1..(1 + expectedLength)]);
                BigInteger Y = new BigInteger(1, encoded[(1 + expectedLength)..]);

                p = ValidatePoint(X, Y);
                break;
            }

            case 0x06: // hybrid
            case 0x07: // hybrid
            {
                if (encoded.Length != (2 * expectedLength + 1))
                    throw new ArgumentException("Incorrect length for hybrid encoding", nameof(encoded));

                BigInteger X = new BigInteger(1, encoded[1..(1 + expectedLength)]);
                BigInteger Y = new BigInteger(1, encoded[(1 + expectedLength)..]);

                if (Y.TestBit(0) != (type == 0x07))
                    throw new ArgumentException("Inconsistent Y coordinate in hybrid encoding", nameof(encoded));

                p = ValidatePoint(X, Y);
                break;
            }

            default:
                throw new FormatException($"Invalid point encoding type: 0x{type:X2}");
            }

            if (type != 0x00 && p.IsInfinity)
                throw new ArgumentException("Invalid infinity encoding", nameof(encoded));

            return p;
        }
#endif

        private class DefaultLookupTable
            : AbstractECLookupTable
        {
            private readonly ECCurve m_outer;
            private readonly byte[] m_table;
            private readonly int m_size;

            internal DefaultLookupTable(ECCurve outer, byte[] table, int size)
            {
                m_outer = outer;
                m_table = table;
                m_size = size;
            }

            public override int Size => m_size;

            public override ECPoint Lookup(int index)
            {
                int FE_BYTES = m_outer.FieldElementEncodingLength;
                byte[] x = new byte[FE_BYTES], y = new byte[FE_BYTES];
                int pos = 0;

                for (int i = 0; i < m_size; ++i)
                {
                    byte MASK = (byte)(((i ^ index) - 1) >> 31);

                    for (int j = 0; j < FE_BYTES; ++j)
                    {
                        x[j] ^= (byte)(m_table[pos + j] & MASK);
                        y[j] ^= (byte)(m_table[pos + FE_BYTES + j] & MASK);
                    }

                    pos += (FE_BYTES * 2);
                }

                return CreatePoint(x, y);
            }

            public override ECPoint LookupVar(int index)
            {
                int FE_BYTES = m_outer.FieldElementEncodingLength;
                byte[] x = new byte[FE_BYTES], y = new byte[FE_BYTES];
                int pos = index * FE_BYTES * 2;

                for (int j = 0; j < FE_BYTES; ++j)
                {
                    x[j] = m_table[pos + j];
                    y[j] = m_table[pos + FE_BYTES + j];
                }

                return CreatePoint(x, y);
            }

            private ECPoint CreatePoint(byte[] x, byte[] y)
            {
                ECFieldElement X = m_outer.FromBigInteger(new BigInteger(1, x));
                ECFieldElement Y = m_outer.FromBigInteger(new BigInteger(1, y));
                return m_outer.CreateRawPoint(X, Y);
            }
        }
    }

    /// <summary>Base class for curves over a prime field.</summary>
    public abstract class AbstractFpCurve
        : ECCurve
    {
        private static readonly ConcurrentDictionary<BigInteger, bool> KnownPrimes =
            new ConcurrentDictionary<BigInteger, bool>();

        /// <summary>Create a new <see cref="AbstractFpCurve"/>.</summary>
        /// <param name="q">The q.</param>
        protected AbstractFpCurve(BigInteger q)
            : this(q, isInternal: false)
        {
        }

        internal AbstractFpCurve(BigInteger q, bool isInternal)
            : base(FiniteFields.GetPrimeField(q))
        {
            if (isInternal)
            {
                KnownPrimes.AddOrUpdate(q, true, (key, value) => true);
            }
            else if (!KnownPrimes.ContainsKey(q))
            {
                ImplCheckQ(q);
                KnownPrimes.TryAdd(q, false);
            }
        }

        /// <inheritdoc/>
        public override bool IsValidFieldElement(BigInteger x) =>
            x != null && x.SignValue >= 0 && x.CompareTo(Field.Characteristic) < 0;

        // TODO[api] Add this property (and replace usages of Field.Characteristic)
        //public virtual BigInteger Q => Field.Characteristic;

        /// <inheritdoc/>
        public override ECFieldElement RandomFieldElement(SecureRandom r)
        {
            /*
             * NOTE: BigInteger comparisons in the rejection sampling are not constant-time, so we
             * use the product of two independent elements to mitigate side-channels.
             */
            BigInteger p = Field.Characteristic;
            ECFieldElement fe1 = FromBigInteger(ImplRandomFieldElement(r, p));
            ECFieldElement fe2 = FromBigInteger(ImplRandomFieldElement(r, p));
            return fe1.Multiply(fe2);
        }

        /// <inheritdoc/>
        public override ECFieldElement RandomFieldElementMult(SecureRandom r)
        {
            /*
             * NOTE: BigInteger comparisons in the rejection sampling are not constant-time, so we
             * use the product of two independent elements to mitigate side-channels.
             */
            BigInteger p = Field.Characteristic;
            ECFieldElement fe1 = FromBigInteger(ImplRandomFieldElementMult(r, p));
            ECFieldElement fe2 = FromBigInteger(ImplRandomFieldElementMult(r, p));
            return fe1.Multiply(fe2);
        }

        /// <inheritdoc/>
        protected override ECPoint DecompressPoint(int yTilde, BigInteger X1)
        {
            ECFieldElement x = FromBigInteger(X1);
            ECFieldElement rhs = x.Square().Add(A).Multiply(x).Add(B);
            ECFieldElement y = rhs.Sqrt();

            /*
             * If y is not a square, then we haven't got a point on the curve
             */
            if (y == null)
                throw new ArgumentException("Invalid point compression", nameof(X1));

            if (y.TestBitZero() != (yTilde == 1))
            {
                // Use the other root
                y = y.Negate();
            }

            return CreateRawPoint(x, y);
        }

        private static void ImplCheckQ(BigInteger q)
        {
            int maxBitLength = Properties.GetInt32(Properties.ECFpMaxSize, 1042); // 2 * 521
            if (q.BitLength > maxBitLength)
                throw new ArgumentException("Fp q value out of range", nameof(q));

            if (!ImplIsPrime(q))
                throw new ArgumentException("Fp q value not prime", nameof(q));
        }

        private static int ImplGetIterations(int bits, int certainty)
        {
            /*
             * NOTE: We enforce a minimum 'certainty' of 100 for bits >= 1024 (else 80). Where the
             * certainty is higher than the FIPS 186-4 tables (C.2/C.3) cater to, extra iterations
             * are added at the "worst case rate" for the excess.
             */
            if (bits >= 1536)
            {
                return certainty <= 100 ? 3
                    : certainty <= 128 ? 4
                    : 4 + (certainty - 128 + 1) / 2;
            }
            else if (bits >= 1024)
            {
                return certainty <= 100 ? 4
                    : certainty <= 112 ? 5
                    : 5 + (certainty - 112 + 1) / 2;
            }
            else if (bits >= 512)
            {
                return certainty <= 80 ? 5
                    : certainty <= 100 ? 7
                    : 7 + (certainty - 100 + 1) / 2;
            }
            else
            {
                return certainty <= 80 ? 40
                    : 40 + (certainty - 80 + 1) / 2;
            }
        }

        private static bool ImplIsPrime(BigInteger q)
        {
            if (Primes.HasAnySmallFactors(q))
                return false;

            int certainty = Properties.GetInt32(Properties.ECFpCertainty, 100);
            int iterations = ImplGetIterations(q.BitLength, certainty);

            return Primes.IsMRProbablePrime(q, SecureRandom.ArbitraryRandom, iterations);
        }

        private static BigInteger ImplRandomFieldElement(SecureRandom r, BigInteger p)
        {
            BigInteger x;
            do
            {
                x = BigIntegers.CreateRandomBigInteger(p.BitLength, r);
            }
            while (x.CompareTo(p) >= 0);
            return x;
        }

        private static BigInteger ImplRandomFieldElementMult(SecureRandom r, BigInteger p)
        {
            BigInteger x;
            do
            {
                x = BigIntegers.CreateRandomBigInteger(p.BitLength, r);
            }
            while (x.SignValue <= 0 || x.CompareTo(p) >= 0);
            return x;
        }
    }

    /// <summary>Elliptic curve over Fp.</summary>
    public class FpCurve
        : AbstractFpCurve
    {
        private const int FP_DEFAULT_COORDS = COORD_JACOBIAN_MODIFIED;

        /// <summary>The r.</summary>
        protected readonly BigInteger m_q, m_r;
        /// <summary>The infinity.</summary>
        protected readonly FpPoint m_infinity;

        /// <summary>Create a new <see cref="FpCurve"/>.</summary>
        /// <param name="q">The q.</param>
        /// <param name="a">The first operand.</param>
        /// <param name="b">The second operand.</param>
        [Obsolete("Use constructor taking order/cofactor")]
        public FpCurve(BigInteger q, BigInteger a, BigInteger b)
            : this(q, a, b, null, null)
        {
        }

        /// <summary>Create a new <see cref="FpCurve"/>.</summary>
        /// <param name="q">The q.</param>
        /// <param name="a">The first operand.</param>
        /// <param name="b">The second operand.</param>
        /// <param name="order">The order.</param>
        /// <param name="cofactor">The cofactor.</param>
        public FpCurve(BigInteger q, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor)
            : this(q, a, b, order, cofactor, isInternal: false)
        {
        }

        internal FpCurve(BigInteger q, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor,
            bool isInternal)
            : base(q, isInternal)
        {
            m_q = q;
            m_r = FpFieldElement.CalculateResidue(q);
            m_infinity = new FpPoint(this, null, null);

            m_a = FromBigInteger(a);
            m_b = FromBigInteger(b);
            m_order = order;
            m_cofactor = cofactor;
            m_coord = FP_DEFAULT_COORDS;
        }

        internal FpCurve(BigInteger q, BigInteger r, ECFieldElement a, ECFieldElement b, BigInteger order,
            BigInteger cofactor)
            : base(q, isInternal: true)
        {
            m_q = q;
            m_r = r;
            m_infinity = new FpPoint(this, null, null);

            m_a = a;
            m_b = b;
            m_order = order;
            m_cofactor = cofactor;
            m_coord = FP_DEFAULT_COORDS;
        }

        /// <inheritdoc/>
        protected override ECCurve CloneCurve() => new FpCurve(m_q, m_r, m_a, m_b, m_order, m_cofactor);

        /// <inheritdoc/>
        public override bool SupportsCoordinateSystem(int coord)
        {
            switch (coord)
            {
            case COORD_AFFINE:
            case COORD_HOMOGENEOUS:
            case COORD_JACOBIAN:
            case COORD_JACOBIAN_MODIFIED:
                return true;
            default:
                return false;
            }
        }

        /// <summary>Gets the q.</summary>
        public virtual BigInteger Q => m_q;

        /// <inheritdoc/>
        public override ECPoint Infinity => m_infinity;

        /// <inheritdoc/>
        public override int FieldSize => m_q.BitLength;

        /// <inheritdoc/>
        public override ECFieldElement FromBigInteger(BigInteger x)
        {
            if (x == null || x.SignValue < 0 || x.CompareTo(m_q) >= 0)
                throw new ArgumentException("value invalid for Fp field element", nameof(x));

            return new FpFieldElement(m_q, m_r, x);
        }

        /// <inheritdoc/>
        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y) =>
            new FpPoint(this, x, y);

        /// <inheritdoc/>
        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) =>
            new FpPoint(this, x, y, zs);

        /// <inheritdoc/>
        public override ECPoint ImportPoint(ECPoint p)
        {
            if (this != p.Curve && CoordinateSystem == COORD_JACOBIAN && !p.IsInfinity)
            {
                switch (p.Curve.CoordinateSystem)
                {
                case COORD_JACOBIAN:
                case COORD_JACOBIAN_CHUDNOVSKY:
                case COORD_JACOBIAN_MODIFIED:
                    return new FpPoint(this,
                        FromBigInteger(p.RawXCoord.ToBigInteger()),
                        FromBigInteger(p.RawYCoord.ToBigInteger()),
                        new ECFieldElement[] { FromBigInteger(p.GetZCoord(0).ToBigInteger()) });
                }
            }

            return base.ImportPoint(p);
        }
    }

    /// <summary>Base class for curves over a binary field.</summary>
    public abstract class AbstractF2mCurve
        : ECCurve
    {
        /// <summary>Calculate the inverse of an element of a binary field.</summary>
        /// <param name="m">The degree of the field.</param>
        /// <param name="ks">The exponents of the reduction polynomial.</param>
        /// <param name="x">The element.</param>
        /// <returns>The inverse.</returns>
        [Obsolete("Will be removed")]
        public static BigInteger Inverse(int m, int[] ks, BigInteger x)
        {
            ulong[] t = Nat.FromBigInteger64(m, x);
            var f2mFieldData = F2mFieldData.From(m, ks);
            var fe = new F2mFieldElement(f2mFieldData, t);
            return fe.Invert().ToBigInteger();
        }

        private static IFiniteField BuildField(int m, int k1, int k2, int k3)
        {
            int maxM = Properties.GetInt32(Properties.ECF2mMaxSize, 1142); // 2 * 571
            if (m > maxM)
                throw new ArgumentException("F2m m value out of range", nameof(m));

            int[] exponents = (k2 | k3) == 0
                ? new int[]{ 0, k1, m }
                : new int[]{ 0, k1, k2, k3, m };

            return FiniteFields.GetBinaryExtensionField(exponents);
        }

        /// <summary>Create a new <see cref="AbstractF2mCurve"/>.</summary>
        /// <param name="m">The m.</param>
        /// <param name="k1">The k 1.</param>
        /// <param name="k2">The k 2.</param>
        /// <param name="k3">The k 3.</param>
        protected AbstractF2mCurve(int m, int k1, int k2, int k3)
            : base(BuildField(m, k1, k2, k3))
        {
        }

        /// <inheritdoc/>
        public override ECPoint CreatePoint(BigInteger x, BigInteger y)
        {
            ECFieldElement X = FromBigInteger(x), Y = FromBigInteger(y);

            switch (CoordinateSystem)
            {
            case COORD_LAMBDA_AFFINE:
            case COORD_LAMBDA_PROJECTIVE:
            {
                if (X.IsZero)
                {
                    if (!Y.Square().Equals(B))
                        throw new ArgumentException();
                }
                else
                {
                    // Y becomes Lambda (X + Y/X) here
                    Y = Y.Divide(X).Add(X);
                }
                break;
            }
            }

            return CreateRawPoint(X, Y);
        }

        /// <inheritdoc/>
        public override bool IsValidFieldElement(BigInteger x) =>
            x != null && x.SignValue >= 0 && x.BitLength <= FieldSize;

        /// <inheritdoc/>
        public override ECFieldElement RandomFieldElement(SecureRandom r)
        {
            int m = FieldSize;
            return FromBigInteger(BigIntegers.CreateRandomBigInteger(m, r));
        }

        /// <inheritdoc/>
        public override ECFieldElement RandomFieldElementMult(SecureRandom r)
        {
            /*
             * NOTE: BigInteger comparisons in the rejection sampling are not constant-time, so we
             * use the product of two independent elements to mitigate side-channels.
             */
            int m = FieldSize;
            ECFieldElement fe1 = FromBigInteger(ImplRandomFieldElementMult(r, m));
            ECFieldElement fe2 = FromBigInteger(ImplRandomFieldElementMult(r, m));
            return fe1.Multiply(fe2);
        }

        /// <inheritdoc/>
        protected override ECPoint DecompressPoint(int yTilde, BigInteger X1)
        {
            ECFieldElement xp = FromBigInteger(X1), yp = null;
            if (xp.IsZero)
            {
                yp = B.Sqrt();
            }
            else
            {
                ECFieldElement beta = xp.Square().Invert().Multiply(B).Add(A).Add(xp);
                ECFieldElement z = SolveQuadraticEquation(beta);

                if (z != null)
                {
                    if (z.TestBitZero() != (yTilde == 1))
                    {
                        z = z.AddOne();
                    }

                    switch (CoordinateSystem)
                    {
                    case COORD_LAMBDA_AFFINE:
                    case COORD_LAMBDA_PROJECTIVE:
                    {
                        yp = z.Add(xp);
                        break;
                    }
                    default:
                    {
                        yp = z.Multiply(xp);
                        break;
                    }
                    }
                }
            }

            if (yp == null)
                throw new ArgumentException("Invalid point compression", nameof(X1));

            return CreateRawPoint(xp, yp);
        }

        /**
         * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
         * D.1.6) The other solution is <code>z + 1</code>.
         *
         * @param beta
         *            The value to solve the quadratic equation for.
         * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
         *         <code>null</code> if no solution exists.
         */
        internal ECFieldElement SolveQuadraticEquation(ECFieldElement beta)
        {
            AbstractF2mFieldElement betaF2m = (AbstractF2mFieldElement)beta;

            bool fastTrace = betaF2m.HasFastTrace;
            if (fastTrace && 0 != betaF2m.Trace())
                return null;

            int m = FieldSize;

            // For odd m, use the half-trace
            if (0 != (m & 1))
            {
                ECFieldElement r = betaF2m.HalfTrace();
                if (fastTrace || r.Square().Add(r).Add(beta).IsZero)
                    return r;

                return null;
            }

            if (beta.IsZero)
                return beta;

            ECFieldElement gamma, z, zeroElement = FromBigInteger(BigInteger.Zero);

            do
            {
                ECFieldElement t = FromBigInteger(BigInteger.Arbitrary(m));
                z = zeroElement;
                ECFieldElement w = beta;
                for (int i = 1; i < m; i++)
                {
                    ECFieldElement w2 = w.Square();
                    z = z.Square().Add(w2.Multiply(t));
                    w = w2.Add(beta);
                }
                if (!w.IsZero)
                    return null;
                gamma = z.Square().Add(z);
            }
            while (gamma.IsZero);

            return z;
        }

        /// <summary>Returns true if this is a Koblitz curve (ABC curve).</summary>
        public virtual bool IsKoblitz =>
            m_order != null && m_cofactor != null && m_b.IsOne && (m_a.IsZero || m_a.IsOne);

        private static BigInteger ImplRandomFieldElementMult(SecureRandom r, int m)
        {
            BigInteger x;
            do
            {
                x = BigIntegers.CreateRandomBigInteger(m, r);
            }
            while (x.SignValue <= 0);
            return x;
        }
    }

    /// <summary>Elliptic curves over F2m.</summary>
    /// <remarks>
    /// The Weierstrass equation is given by: <c>y^2 + xy = x^3 + ax^2 + b</c>.
    /// </remarks>
    public class F2mCurve
        : AbstractF2mCurve
    {
        private const int F2M_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

        private readonly F2mFieldData m_f2mFieldData;

        /**
         * The point at infinity on this curve.
         */
        protected readonly F2mPoint m_infinity;

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
        [Obsolete("Use constructor taking order/cofactor")]
        public F2mCurve(
            int m,
            int k,
            BigInteger a,
            BigInteger b)
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
         * @param order The order of the main subgroup of the elliptic curve.
         * @param cofactor The cofactor of the elliptic curve, i.e.
         * <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>.
         */
        public F2mCurve(
            int m,
            int k,
            BigInteger a,
            BigInteger b,
            BigInteger order,
            BigInteger cofactor)
            : this(m, k, 0, 0, a, b, order, cofactor)
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
        [Obsolete("Use constructor taking order/cofactor")]
        public F2mCurve(
            int m,
            int k1,
            int k2,
            int k3,
            BigInteger a,
            BigInteger b)
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
         * @param order The order of the main subgroup of the elliptic curve.
         * @param cofactor The cofactor of the elliptic curve, i.e.
         * <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>.
         */
        public F2mCurve(int m, int k1, int k2, int k3, BigInteger a, BigInteger b, BigInteger order,
            BigInteger cofactor)
            : base(m, k1, k2, k3)
        {
            m_f2mFieldData = F2mFieldData.From(m, k1, k2, k3);

            m_order = order;
            m_cofactor = cofactor;
            m_infinity = new F2mPoint(this, null, null);

            m_a = FromBigInteger(a);
            m_b = FromBigInteger(b);
            m_coord = F2M_DEFAULT_COORDS;
        }

        internal F2mCurve(int m, int k1, int k2, int k3, ECFieldElement a, ECFieldElement b, BigInteger order,
            BigInteger cofactor)
            : base(m, k1, k2, k3)
        {
            m_f2mFieldData = F2mFieldData.From(m, k1, k2, k3);

            m_order = order;
            m_cofactor = cofactor;
            m_infinity = new F2mPoint(this, null, null);

            m_a = a;
            m_b = b;
            m_coord = F2M_DEFAULT_COORDS;
        }

        private F2mCurve(F2mFieldData f2mFieldData, ECFieldElement a, ECFieldElement b, BigInteger order,
            BigInteger cofactor)
            : base(f2mFieldData._m, f2mFieldData.K1, f2mFieldData.K2, f2mFieldData.K3)
        {
            m_f2mFieldData = f2mFieldData;

            m_order = order;
            m_cofactor = cofactor;
            m_infinity = new F2mPoint(this, null, null);

            m_a = a;
            m_b = b;
            m_coord = F2M_DEFAULT_COORDS;
        }

        /// <inheritdoc/>
        protected override ECCurve CloneCurve() => new F2mCurve(m_f2mFieldData, m_a, m_b, m_order, m_cofactor);

        /// <inheritdoc/>
        public override bool SupportsCoordinateSystem(int coord)
        {
            switch (coord)
            {
            case COORD_AFFINE:
            case COORD_HOMOGENEOUS:
            case COORD_LAMBDA_PROJECTIVE:
                return true;
            default:
                return false;
            }
        }

        /// <inheritdoc/>
        protected override ECMultiplier CreateDefaultMultiplier()
        {
            if (IsKoblitz)
                return new WTauNafMultiplier();

            return base.CreateDefaultMultiplier();
        }

        /// <inheritdoc/>
        public override int FieldSize => M;

        /// <inheritdoc/>
        public override ECFieldElement FromBigInteger(BigInteger x)
        {
            if (x == null || x.SignValue < 0 || x.BitLength > M)
                throw new ArgumentException("value invalid for F2m field element", nameof(x));

            ulong[] t = Nat.FromBigInteger64(M, x);

            return new F2mFieldElement(m_f2mFieldData, t);
        }

        /// <inheritdoc/>
        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y) =>
            new F2mPoint(this, x, y);

        /// <inheritdoc/>
        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) =>
            new F2mPoint(this, x, y, zs);

        /// <inheritdoc/>
        public override ECPoint Infinity => m_infinity;

        /// <summary>Gets the m.</summary>
        public int M => m_f2mFieldData._m;

        /// <summary>Return true if curve uses a Trinomial basis.</summary>
        public bool IsTrinomial() => K2 == 0 && K3 == 0;

        /// <summary>Gets the k 1.</summary>
        public int K1 => m_f2mFieldData.K1;

        /// <summary>Gets the k 2.</summary>
        public int K2 => m_f2mFieldData.K2;

        /// <summary>Gets the k 3.</summary>
        public int K3 => m_f2mFieldData.K3;

        /// <inheritdoc/>
        public override ECLookupTable CreateCacheSafeLookupTable(ECPoint[] points, int off, int len)
        {
            int FE_LONGS = BinPolys.Size(M);

            ulong[] table = new ulong[len * FE_LONGS * 2];
            {
                int pos = 0;
                for (int i = 0; i < len; ++i)
                {
                    ECPoint p = points[off + i];
                    BinPolys.Copy(FE_LONGS, ((F2mFieldElement)p.RawXCoord).m_x, 0, table, pos); pos += FE_LONGS;
                    BinPolys.Copy(FE_LONGS, ((F2mFieldElement)p.RawYCoord).m_x, 0, table, pos); pos += FE_LONGS;
                }
            }

            return new DefaultF2mLookupTable(this, table, len);
        }

        private class DefaultF2mLookupTable
            : AbstractECLookupTable
        {
            private readonly F2mCurve m_outer;
            private readonly ulong[] m_table;
            private readonly int m_size;

            internal DefaultF2mLookupTable(F2mCurve outer, ulong[] table, int size)
            {
                m_outer = outer;
                m_table = table;
                m_size = size;
            }

            public override int Size => m_size;

            public override ECPoint Lookup(int index)
            {
                int FE_LONGS = BinPolys.Size(m_outer.M);
                ulong[] x = new ulong[FE_LONGS], y = new ulong[FE_LONGS];
                int pos = 0;

                for (int i = 0; i < m_size; ++i)
                {
                    ulong MASK = (ulong)(long)(((i ^ index) - 1) >> 31);

                    for (int j = 0; j < FE_LONGS; ++j)
                    {
                        x[j] ^= m_table[pos + j] & MASK;
                        y[j] ^= m_table[pos + FE_LONGS + j] & MASK;
                    }

                    pos += (FE_LONGS * 2);
                }

                return CreatePoint(x, y);
            }

            public override ECPoint LookupVar(int index)
            {
                int FE_LONGS = BinPolys.Size(m_outer.M);
                ulong[] x = new ulong[FE_LONGS], y = new ulong[FE_LONGS];
                int pos = index * FE_LONGS * 2;

                for (int j = 0; j < FE_LONGS; ++j)
                {
                    x[j] = m_table[pos + j];
                    y[j] = m_table[pos + FE_LONGS + j];
                }

                return CreatePoint(x, y);
            }

            private ECPoint CreatePoint(ulong[] x, ulong[] y)
            {
                ECFieldElement X = new F2mFieldElement(m_outer.m_f2mFieldData, x);
                ECFieldElement Y = new F2mFieldElement(m_outer.m_f2mFieldData, y);
                return m_outer.CreateRawPoint(X, Y);
            }
        }
    }
}
