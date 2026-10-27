using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 GeneralString type.</summary>
    public class DerGeneralString
        : DerStringBase
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerGeneralString), Asn1Tags.GeneralString) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

        /// <summary>Return an <see cref="DerGeneralString"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DerGeneralString"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DerGeneralString"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DerGeneralString GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerGeneralString derGeneralString)
                return derGeneralString;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerGeneralString converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerGeneralString)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct general string from byte[]", nameof(obj), e);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        /// <summary>Return an <see cref="DerGeneralString"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DerGeneralString"/>.</returns>
        public static DerGeneralString GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerGeneralString)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);
        }

        /// <summary>Return an <see cref="DerGeneralString"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="DerGeneralString"/>, or null if <paramref name="element"/> is null.</returns>
        public static DerGeneralString GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerGeneralString existing)
                return existing;

            return null;
        }

        /// <summary>Return an <see cref="DerGeneralString"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DerGeneralString"/>.</returns>
        public static DerGeneralString GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerGeneralString)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        private readonly byte[] m_contents;

        /// <summary>Create a new <see cref="DerGeneralString"/>.</summary>
        /// <param name="str">The str.</param>
        public DerGeneralString(string str)
        {
            if (str == null)
                throw new ArgumentNullException("str");

            m_contents = Strings.ToAsciiByteArray(str);
        }

        /// <summary>Create a new <see cref="DerGeneralString"/>.</summary>
        /// <param name="contents">The contents.</param>
        public DerGeneralString(byte[] contents)
            : this(contents, true)
        {
        }

        internal DerGeneralString(byte[] contents, bool clone)
        {
            if (null == contents)
                throw new ArgumentNullException(nameof(contents));

            m_contents = clone ? Arrays.Clone(contents) : contents;
        }

        /// <inheritdoc/>
        public override string GetString()
        {
            return Strings.FromAsciiByteArray(m_contents);
        }

        /// <summary>Return the octets.</summary>
        public byte[] GetOctets()
        {
            return Arrays.Clone(m_contents);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.GeneralString, m_contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.GeneralString, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new PrimitiveDerEncoding(tagClass, tagNo, m_contents);
        }

        /// <inheritdoc/>
        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            DerGeneralString that = asn1Object as DerGeneralString;
            return null != that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        /// <inheritdoc/>
        protected override int Asn1GetHashCode()
        {
            return Arrays.GetHashCode(m_contents);
        }

        internal static DerGeneralString CreatePrimitive(byte[] contents)
        {
            return new DerGeneralString(contents, false);
        }
    }
}
