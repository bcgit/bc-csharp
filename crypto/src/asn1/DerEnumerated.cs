using System;
using System.IO;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 ENUMERATED type.</summary>
    public class DerEnumerated
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerEnumerated), Asn1Tags.Enumerated) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

        private static readonly DerEnumerated[] SmallConstants = new DerEnumerated[16];

        /// <summary>Return an <see cref="DerEnumerated"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DerEnumerated"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DerEnumerated"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DerEnumerated GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerEnumerated derEnumerated)
                return derEnumerated;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerEnumerated converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerEnumerated)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct enumerated from byte[]", nameof(obj), e);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        /// <summary>Return an <see cref="DerEnumerated"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DerEnumerated"/>.</returns>
        public static DerEnumerated GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerEnumerated)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);
        }

        /// <summary>Return an <see cref="DerEnumerated"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="DerEnumerated"/>, or null if <paramref name="element"/> is null.</returns>
        public static DerEnumerated GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerEnumerated existing)
                return existing;

            return null;
        }

        /// <summary>Return an <see cref="DerEnumerated"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DerEnumerated"/>.</returns>
        public static DerEnumerated GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerEnumerated)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        public static DerEnumerated ValueOf(int value)
        {
            if (value >= 0L && value < SmallConstants.Length)
                return SmallConstants[value];

#pragma warning disable CS0618 // Type or member is obsolete
            return new DerEnumerated(value);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static DerEnumerated ValueOf(long value)
        {
            if (value >= 0L && value < SmallConstants.Length)
                return SmallConstants[(int)value];

#pragma warning disable CS0618 // Type or member is obsolete
            return new DerEnumerated(value);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        static DerEnumerated()
        {
            for (int i = 0; i < SmallConstants.Length; ++i)
            {
#pragma warning disable CS0618 // Type or member is obsolete
                SmallConstants[i] = new DerEnumerated(i);
#pragma warning restore CS0618 // Type or member is obsolete
            }
        }

        private readonly byte[] m_contents;
        private readonly int m_start;

        /// <summary>Create a new <see cref="DerEnumerated"/>.</summary>
        /// <param name="val">The val.</param>
        [Obsolete("Use ValueOf instead.")]
        public DerEnumerated(int val)
        {
            m_contents = BigInteger.ValueOf(val).ToByteArray();
            m_start = 0;
        }

        /// <summary>Create a new <see cref="DerEnumerated"/>.</summary>
        /// <param name="val">The val.</param>
        [Obsolete("Use ValueOf instead.")]
        public DerEnumerated(long val)
        {
            m_contents = BigInteger.ValueOf(val).ToByteArray();
            m_start = 0;
        }

        /// <summary>Create a new <see cref="DerEnumerated"/>.</summary>
        /// <param name="val">The val.</param>
        public DerEnumerated(BigInteger val)
        {
            m_contents = val.ToByteArray();
            m_start = 0;
        }

        /// <summary>Create a new <see cref="DerEnumerated"/>.</summary>
        /// <param name="contents">The contents.</param>
        public DerEnumerated(byte[] contents)
            : this(contents, clone: true)
        {
        }

        internal DerEnumerated(byte[] contents, bool clone)
        {
            if (DerInteger.IsMalformed(contents))
                throw new ArgumentException("malformed enumerated", nameof(contents));

            m_contents = clone ? Arrays.Clone(contents) : contents;
            m_start = DerInteger.SignBytesToSkip(m_contents);
        }

        /// <summary>Gets the value.</summary>
        // NB: The BigInteger constructor tolerates any redundant sign bytes (per 'AllowUnsafe')
        public BigInteger Value => new BigInteger(m_contents);

        public bool HasValue(int x)
        {
            return (m_contents.Length - m_start) <= 4
                && DerInteger.IntValue(m_contents, m_start, DerInteger.SignExtSigned) == x;
        }

        public bool HasValue(BigInteger x)
        {
            return null != x
                // Fast check to avoid allocation
                && DerInteger.IntValue(m_contents, m_start, DerInteger.SignExtSigned) == x.IntValue
                && Value.Equals(x);
        }

        /// <summary>Gets the int value exact.</summary>
        public int IntValueExact => TryGetIntValueExact(out int result) ? result
            : throw new ArithmeticException("ASN.1 Enumerated out of int range");

        public long LongValueExact => TryGetLongValueExact(out long result) ? result
            : throw new ArithmeticException("ASN.1 Enumerated out of long range");

        public bool TryGetIntValueExact(out int value)
        {
            int count = m_contents.Length - m_start;
            if (count > 4)
            {
                value = default;
                return false;
            }

            value = DerInteger.IntValue(m_contents, m_start, DerInteger.SignExtSigned);
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

            value = DerInteger.LongValue(m_contents, m_start, DerInteger.SignExtSigned);
            return true;
        }

        public bool IsNegative => (m_contents[m_start] & 0x80) != 0;

        internal override IAsn1Encoding GetEncoding(int encoding) =>
            new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.Enumerated, m_contents);

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo) =>
            new PrimitiveEncoding(tagClass, tagNo, m_contents);

        internal sealed override DerEncoding GetEncodingDer() =>
            new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.Enumerated, m_contents);

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo) =>
            new PrimitiveDerEncoding(tagClass, tagNo, m_contents);

        /// <inheritdoc/>
        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return asn1Object is DerEnumerated that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        /// <inheritdoc/>
        protected override int Asn1GetHashCode() => Arrays.GetHashCode(m_contents);

        public override string ToString() => Value.ToString();

        private static DerEnumerated CreatePrimitive(byte[] contents)
        {
            if (contents.Length == 1 && contents[0] < SmallConstants.Length)
                return SmallConstants[contents[0]];

            return new DerEnumerated(contents, clone: false);
        }

        internal static DerEnumerated CreatePrimitive(DefiniteLengthInputStream defIn)
        {
            if (defIn.Remaining == 1)
            {
                int value = defIn.ReadByte();
                if (value < SmallConstants.Length)
                    return SmallConstants[value];

                return new DerEnumerated(new byte[1] { (byte)value }, clone: false);
            }

            return new DerEnumerated(defIn.ToArray(), clone: false);
        }
    }
}
