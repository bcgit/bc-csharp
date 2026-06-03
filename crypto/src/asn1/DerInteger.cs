using System;
using System.IO;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
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

        public const string AllowUnsafeProperty = "Org.BouncyCastle.Asn1.AllowUnsafeInteger";

        private static readonly DerInteger[] SmallConstants = new DerInteger[17];

        public static readonly DerInteger Zero;
        public static readonly DerInteger One;
        public static readonly DerInteger Two;
        public static readonly DerInteger Three;
        public static readonly DerInteger Four;
        public static readonly DerInteger Five;

        internal static bool AllowUnsafe()
        {
            string allowUnsafeValue = Platform.GetEnvironmentVariable(AllowUnsafeProperty);
            return allowUnsafeValue != null && Platform.EqualsIgnoreCase("true", allowUnsafeValue);
        }

        internal const int SignExtSigned = -1;
        internal const int SignExtUnsigned = 0xFF;

        private readonly byte[] m_contents;
        private readonly int m_start;

        /**
         * return an integer from the passed in object
         *
         * @exception ArgumentException if the object cannot be converted.
         */
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

        /**
         * return an Integer from a tagged object.
         *
         * @param taggedObject the tagged object holding the object we want
         * @param declaredExplicit true if the object is meant to be explicitly tagged false otherwise.
         * @exception ArgumentException if the tagged object cannot  be converted.
         */
        public static DerInteger GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerInteger)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);
        }

        public static DerInteger GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerInteger existing)
                return existing;

            return null;
        }

        public static DerInteger GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerInteger)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        public static DerInteger ValueOf(int value)
        {
            if (value >= 0L && value < SmallConstants.Length)
                return SmallConstants[value];

#pragma warning disable CS0618 // Type or member is obsolete
            return new DerInteger(value);
#pragma warning restore CS0618 // Type or member is obsolete
        }

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

        [Obsolete("Use ValueOf instead.")]
        public DerInteger(int value)
        {
            m_contents = BigInteger.ValueOf(value).ToByteArray();
            m_start = 0;
        }

        [Obsolete("Use ValueOf instead.")]
        public DerInteger(long value)
        {
            m_contents = BigInteger.ValueOf(value).ToByteArray();
            m_start = 0;
        }

        public DerInteger(BigInteger value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            m_contents = value.ToByteArray();
            m_start = 0;
        }

        public DerInteger(byte[] bytes)
            : this(bytes, clone: true)
        {
        }

        internal DerInteger(byte[] bytes, bool clone)
        {
            if (IsMalformed(bytes))
                throw new ArgumentException("malformed integer", nameof(bytes));

            m_contents = clone ? Arrays.Clone(bytes) : bytes;
            m_start = SignBytesToSkip(bytes);
        }

        /// <summary>Force the ASN.1 INTEGER encoding to be interpreted as unsigned.</summary>
        /// <remarks>
        /// In some cases positive values get crammed into a space that's not quite big enough...
        /// NB: The BigInteger constructor tolerates any redundant sign bytes (per 'AllowUnsafe').
        /// </remarks>
        public BigInteger PositiveValue => new BigInteger(1, m_contents);

        // NB: The BigInteger constructor tolerates any redundant sign bytes (per 'AllowUnsafe')
        public BigInteger Value => new BigInteger(m_contents);

        public bool HasValue(int x)
        {
            return (m_contents.Length - m_start) <= 4
                && IntValue(m_contents, m_start, SignExtSigned) == x;
        }

        public bool HasValue(long x)
        {
            return (m_contents.Length - m_start) <= 8
                && LongValue(m_contents, m_start, SignExtSigned) == x;
        }

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

        public int IntValueExact => TryGetIntValueExact(out int result) ? result
            : throw new ArithmeticException("ASN.1 Integer out of int range");

        /// <summary>Force the ASN.1 INTEGER encoding to be interpreted as unsigned.</summary>
        /// <remarks>
        /// In some cases positive values get crammed into a space that's not quite big enough...
        /// </remarks>
        public long LongPositiveValueExact => TryGetLongPositiveValueExact(out long result) ? result
            : throw new ArithmeticException("ASN.1 Integer out of positive long range");

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

        public bool IsNegative => (m_contents[m_start] & 0x80) != 0;

        internal override IAsn1Encoding GetEncoding(int encoding) =>
            new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.Integer, m_contents);

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo) =>
            new PrimitiveEncoding(tagClass, tagNo, m_contents);

        internal sealed override DerEncoding GetEncodingDer() =>
            new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.Integer, m_contents);

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo) =>
            new PrimitiveDerEncoding(tagClass, tagNo, m_contents);

        protected override int Asn1GetHashCode() => Arrays.GetHashCode(m_contents);

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return asn1Object is DerInteger that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        public override string ToString() => Value.ToString();

        internal static DerInteger CreatePrimitive(byte[] contents) => new DerInteger(contents, clone: false);

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

        /**
         * Apply the correct validation for an INTEGER primitive following the BER rules.
         *
         * @param bytes The raw encoding of the integer.
         * @return true if the (in)put fails this validation.
         */
        internal static bool IsMalformed(byte[] bytes)
        {
            switch (bytes.Length)
            {
            case 0:
                return true;
            case 1:
                return false;
            default:
                return (sbyte)bytes[0] == ((sbyte)bytes[1] >> 7) && !AllowUnsafe();
            }
        }

        internal static int SignBytesToSkip(byte[] bytes)
        {
            int pos = 0, last = bytes.Length - 1;
            while (pos < last
                && (sbyte)bytes[pos] == ((sbyte)bytes[pos + 1] >> 7))
            {
                ++pos;
            }
            return pos;
        }
    }
}
