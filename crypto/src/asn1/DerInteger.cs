using System;
using System.IO;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 INTEGER type.</summary>
    public class DerInteger
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerInteger), Asn1Tags.Integer) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

        /// <summary>
        /// The <c>AllowUnsafeProperty</c> constant, with the value <c>Org.BouncyCastle.Asn1.AllowUnsafeInteger</c>.
        /// </summary>
        [Obsolete("Use 'Properties.Asn1AllowUnsafeInteger' instead")]
        public const string AllowUnsafeProperty = "Org.BouncyCastle.Asn1.AllowUnsafeInteger";

        private static readonly DerInteger[] SmallConstants = new DerInteger[64];

        /// <summary>The value 0.</summary>
        public static readonly DerInteger Zero;
        /// <summary>The value 1.</summary>
        public static readonly DerInteger One;
        /// <summary>The value 2.</summary>
        public static readonly DerInteger Two;
        /// <summary>The value 3.</summary>
        public static readonly DerInteger Three;
        /// <summary>The value 4.</summary>
        public static readonly DerInteger Four;
        /// <summary>The value 5.</summary>
        public static readonly DerInteger Five;

        internal static bool AllowUnsafe() => Properties.GetBoolean(Properties.Asn1AllowUnsafeInteger, false);

        internal const int SignExtSigned = -1;
        internal const int SignExtUnsigned = 0xFF;

        public static DerInteger GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerInteger derInteger)
                return derInteger;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerInteger converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerInteger)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct integer from byte[]", nameof(obj), e);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        public static DerInteger GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerInteger)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);
        }

        /// <summary>Return an <see cref="DerInteger"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="DerInteger"/>, or null if <paramref name="element"/> is null.</returns>
        public static DerInteger GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerInteger existing)
                return existing;

            return null;
        }

        /// <summary>Return an <see cref="DerInteger"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DerInteger"/>.</returns>
        public static DerInteger GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerInteger)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        /// <summary>Create an integer with the given value.</summary>
        /// <param name="value">The value.</param>
        /// <returns>The integer.</returns>
        public static DerInteger ValueOf(int value)
        {
            if (value >= 0L && value < SmallConstants.Length)
                return SmallConstants[value];

#pragma warning disable CS0618 // Type or member is obsolete
            return new DerInteger(value);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Create an integer with the given value.</summary>
        /// <param name="value">The value.</param>
        /// <returns>The integer.</returns>
        public static DerInteger ValueOf(long value)
        {
            if (value >= 0L && value < SmallConstants.Length)
                return SmallConstants[(int)value];

#pragma warning disable CS0618 // Type or member is obsolete
            return new DerInteger(value);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        static DerInteger()
        {
            for (int i = 0; i < SmallConstants.Length; ++i)
            {
#pragma warning disable CS0618 // Type or member is obsolete
                SmallConstants[i] = new DerInteger(i);
#pragma warning restore CS0618 // Type or member is obsolete
            }

            Zero = SmallConstants[0];
            One = SmallConstants[1];
            Two = SmallConstants[2];
            Three = SmallConstants[3];
            Four = SmallConstants[4];
            Five = SmallConstants[5];
        }

        private readonly byte[] m_contents;
        private readonly int m_start;

        /// <summary>Create a new <see cref="DerInteger"/>.</summary>
        /// <param name="value">The value.</param>
        [Obsolete("Use ValueOf instead.")]
        public DerInteger(int value)
        {
            m_contents = BigInteger.ValueOf(value).ToByteArray();
            m_start = 0;
        }

        /// <summary>Create a new <see cref="DerInteger"/>.</summary>
        /// <param name="value">The value.</param>
        [Obsolete("Use ValueOf instead.")]
        public DerInteger(long value)
        {
            m_contents = BigInteger.ValueOf(value).ToByteArray();
            m_start = 0;
        }

        /// <summary>Create a new <see cref="DerInteger"/>.</summary>
        /// <param name="value">The value.</param>
        public DerInteger(BigInteger value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            m_contents = value.ToByteArray();
            m_start = 0;
        }

        /// <summary>Create a new <see cref="DerInteger"/>.</summary>
        /// <param name="bytes">The bytes.</param>
        public DerInteger(byte[] bytes)
            : this(bytes, clone: true)
        {
        }

        internal DerInteger(byte[] contents, bool clone)
        {
            if (IsMalformed(contents))
                throw new ArgumentException("malformed integer", nameof(contents));

            m_contents = clone ? Arrays.Clone(contents) : contents;
            m_start = SignBytesToSkip(m_contents);
        }

        /// <summary>Force the ASN.1 INTEGER encoding to be interpreted as unsigned.</summary>
        /// <remarks>
        /// In some cases positive values get crammed into a space that's not quite big enough...
        /// NB: The BigInteger constructor tolerates any redundant sign bytes (per 'AllowUnsafe').
        /// </remarks>
        public BigInteger PositiveValue => new BigInteger(1, m_contents);

        /// <summary>Gets the value.</summary>
        // NB: The BigInteger constructor tolerates any redundant sign bytes (per 'AllowUnsafe')
        public BigInteger Value => new BigInteger(m_contents);

        /// <summary>Determine whether the integer equals the given value.</summary>
        /// <param name="x">The value to compare with.</param>
        /// <returns>true if the values are equal, false otherwise.</returns>
        public bool HasValue(int x)
        {
            return (m_contents.Length - m_start) <= 4
                && IntValue(m_contents, m_start, SignExtSigned) == x;
        }

        /// <summary>Determine whether the integer equals the given value.</summary>
        /// <param name="x">The value to compare with.</param>
        /// <returns>true if the values are equal, false otherwise.</returns>
        public bool HasValue(long x)
        {
            return (m_contents.Length - m_start) <= 8
                && LongValue(m_contents, m_start, SignExtSigned) == x;
        }

        /// <summary>Determine whether the integer equals the given value.</summary>
        /// <param name="x">The value to compare with.</param>
        /// <returns>true if the values are equal, false otherwise.</returns>
        public bool HasValue(BigInteger x)
        {
            return null != x
                // Fast check to avoid allocation
                && IntValue(m_contents, m_start, SignExtSigned) == x.IntValue
                && Value.Equals(x);
        }

        /// <summary>Force the ASN.1 INTEGER encoding to be interpreted as unsigned.</summary>
        /// <remarks>
        /// In some cases positive values get crammed into a space that's not quite big enough...
        /// </remarks>
        public int IntPositiveValueExact => TryGetIntPositiveValueExact(out int result) ? result
            : throw new ArithmeticException("ASN.1 Integer out of positive int range");

        /// <summary>Gets the int value exact.</summary>
        public int IntValueExact => TryGetIntValueExact(out int result) ? result
            : throw new ArithmeticException("ASN.1 Integer out of int range");

        /// <summary>Force the ASN.1 INTEGER encoding to be interpreted as unsigned.</summary>
        /// <remarks>
        /// In some cases positive values get crammed into a space that's not quite big enough...
        /// </remarks>
        public long LongPositiveValueExact => TryGetLongPositiveValueExact(out long result) ? result
            : throw new ArithmeticException("ASN.1 Integer out of positive long range");

        /// <summary>Gets the long value exact.</summary>
        public long LongValueExact => TryGetLongValueExact(out long result) ? result
            : throw new ArithmeticException("ASN.1 Integer out of long range");

        /// <summary>Force the ASN.1 INTEGER encoding to be interpreted as unsigned.</summary>
        /// <remarks>
        /// In some cases positive values get crammed into a space that's not quite big enough...
        /// </remarks>
        public bool TryGetIntPositiveValueExact(out int value)
        {
            int count = m_contents.Length - m_start;
            if (count > 4 || (count == 4 && IsNegative))
            {
                value = default;
                return false;
            }

            value = IntValue(m_contents, m_start, SignExtUnsigned);
            return true;
        }

        /// <summary>Try to get the value as an int.</summary>
        /// <param name="value">On success, the value.</param>
        /// <returns>true if the value fits in an int, false otherwise.</returns>
        public bool TryGetIntValueExact(out int value)
        {
            int count = m_contents.Length - m_start;
            if (count > 4)
            {
                value = default;
                return false;
            }

            value = IntValue(m_contents, m_start, SignExtSigned);
            return true;
        }

        /// <summary>Force the ASN.1 INTEGER encoding to be interpreted as unsigned.</summary>
        /// <remarks>
        /// In some cases positive values get crammed into a space that's not quite big enough...
        /// </remarks>
        public bool TryGetLongPositiveValueExact(out long value)
        {
            int count = m_contents.Length - m_start;
            if (count > 8 || (count == 8 && IsNegative))
            {
                value = default;
                return false;
            }

            value = LongValue(m_contents, m_start, SignExtSigned);
            return true;
        }

        /// <summary>Try to get the value as a long.</summary>
        /// <param name="value">On success, the value.</param>
        /// <returns>true if the value fits in a long, false otherwise.</returns>
        public bool TryGetLongValueExact(out long value)
        {
            int count = m_contents.Length - m_start;
            if (count > 8)
            {
                value = default;
                return false;
            }

            value = LongValue(m_contents, m_start, SignExtSigned);
            return true;
        }

        /// <summary>Gets a value indicating whether this is negative.</summary>
        public bool IsNegative => (m_contents[m_start] & 0x80) != 0;

        internal override IAsn1Encoding GetEncoding(int encoding) =>
            new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.Integer, m_contents);

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo) =>
            new PrimitiveEncoding(tagClass, tagNo, m_contents);

        internal sealed override DerEncoding GetEncodingDer() =>
            new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.Integer, m_contents);

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo) =>
            new PrimitiveDerEncoding(tagClass, tagNo, m_contents);

        /// <inheritdoc/>
        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return asn1Object is DerInteger that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        /// <inheritdoc/>
        protected override int Asn1GetHashCode() => Arrays.GetHashCode(m_contents);

        /// <inheritdoc/>
        public override string ToString() => Value.ToString();

        internal static DerInteger CreatePrimitive(byte[] contents)
        {
            if (contents.Length == 1 && contents[0] < SmallConstants.Length)
                return SmallConstants[contents[0]];

            return new DerInteger(contents, clone: false);
        }

        internal static DerInteger CreatePrimitive(DefiniteLengthInputStream defIn)
        {
            if (defIn.Remaining == 1)
            {
                int value = defIn.ReadByte();
                if (value < SmallConstants.Length)
                    return SmallConstants[value];

                return new DerInteger(new byte[1] { (byte)value }, clone: false);
            }

            return new DerInteger(defIn.ToArray(), clone: false);
        }

        internal static int GetEncodingLength(BigInteger x) =>
            Asn1OutputStream.GetLengthOfEncodingDL(Asn1Tags.Integer, BigIntegers.GetByteLength(x));

        internal static int IntValue(byte[] bytes, int start, int signExt)
        {
            int length = bytes.Length;
            int pos = System.Math.Max(start, length - 4);

            int val = (sbyte)bytes[pos] & signExt;
            while (++pos < length)
            {
                val = (val << 8) | bytes[pos];
            }
            return val;
        }

        internal static long LongValue(byte[] bytes, int start, int signExt)
        {
            int length = bytes.Length;
            int pos = System.Math.Max(start, length - 8);

            long val = (sbyte)bytes[pos] & signExt;
            while (++pos < length)
            {
                val = (val << 8) | bytes[pos];
            }
            return val;
        }

        /// <summary>
        /// Apply the correct validation for an INTEGER primitive following the BER rules.
        /// </summary>
        /// <param name="contents">The contents octets of the integer.</param>
        /// <returns><c>true</c> if the contents octets fail validation.</returns>
        internal static bool IsMalformed(byte[] contents)
        {
            switch (contents.Length)
            {
            case 0:
                return true;
            case 1:
                return false;
            default:
                return (sbyte)contents[0] == ((sbyte)contents[1] >> 7) && !AllowUnsafe();
            }
        }

        internal static int SignBytesToSkip(byte[] contents)
        {
            int pos = 0, last = contents.Length - 1;
            while (pos < last
                && (sbyte)contents[pos] == ((sbyte)contents[pos + 1] >> 7))
            {
                ++pos;
            }
            return pos;
        }
    }
}
