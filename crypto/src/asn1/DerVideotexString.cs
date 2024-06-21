using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class DerVideotexString
        : DerStringBase
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerVideotexString), Asn1Tags.VideotexString) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

        /**
         * return a videotex string from the passed in object
         *
         * @param obj a DERVideotexString or an object that can be converted into one.
         * @exception IllegalArgumentException if the object cannot be converted.
         * @return a DERVideotexString instance, or null.
         */
        public static DerVideotexString GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerVideotexString derVideotexString)
                return derVideotexString;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerVideotexString converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerVideotexString)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct videotex string from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
        }

        /**
         * return a videotex string from a tagged object.
         *
         * @param taggedObject the tagged object holding the object we want
         * @param declaredExplicit true if the object is meant to be explicitly tagged false otherwise.
         * @exception IllegalArgumentException if the tagged object cannot be converted.
         * @return a DERVideotexString instance, or null.
         */
        public static DerVideotexString GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerVideotexString)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
        }

        public static DerVideotexString GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerVideotexString existing)
                return existing;

            return null;
        }

        public static DerVideotexString GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerVideotexString)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        private readonly byte[] m_contents;

        public DerVideotexString(byte[] contents)
            : this(contents, true)
        {
        }

        internal DerVideotexString(byte[] contents, bool clone)
        {
            if (null == contents)
                throw new ArgumentNullException("contents");

            m_contents = clone ? Arrays.Clone(contents) : contents;
        }

        public override string GetString()
        {
            return Strings.FromByteArray(m_contents);
        }

        public byte[] GetOctets()
        {
            return Arrays.Clone(m_contents);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.VideotexString, m_contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.VideotexString, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new PrimitiveDerEncoding(tagClass, tagNo, m_contents);
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            DerVideotexString that = asn1Object as DerVideotexString;
            return null != that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        protected override int Asn1GetHashCode()
        {
            return Arrays.GetHashCode(m_contents);
        }

        internal static DerVideotexString CreatePrimitive(byte[] contents)
        {
            return new DerVideotexString(contents, false);
        }
    }
}
