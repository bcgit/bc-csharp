using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /**
     * Der UTF8String object.
     */
    public class DerUtf8String
        : DerStringBase
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerUtf8String), Asn1Tags.Utf8String) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

		/**
         * return an UTF8 string from the passed in object.
         *
         * @exception ArgumentException if the object cannot be converted.
         */
        public static DerUtf8String GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerUtf8String derUtf8String)
                return derUtf8String;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerUtf8String converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerUtf8String)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct UTF8 string from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj));
        }

        /**
         * return a UTF8 string from a tagged object.
         *
         * @param taggedObject the tagged object holding the object we want
         * @param declaredExplicit true if the object is meant to be explicitly tagged false otherwise.
         * @exception ArgumentException if the tagged object cannot be converted.
         */
        public static DerUtf8String GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerUtf8String)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
        }

        public static DerUtf8String GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerUtf8String existing)
                return existing;

            return null;
        }

        public static DerUtf8String GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerUtf8String)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        private readonly byte[] m_contents;

        public DerUtf8String(string str)
            : this(Strings.ToUtf8ByteArray(str), false)
        {
        }

        public DerUtf8String(byte[] contents)
            : this(contents, true)
        {
        }

        internal DerUtf8String(byte[] contents, bool clone)
        {
            if (null == contents)
                throw new ArgumentNullException("contents");

            m_contents = clone ? Arrays.Clone(contents) : contents;
        }

        public override string GetString()
        {
            return Strings.FromUtf8ByteArray(m_contents);
        }

		protected override bool Asn1Equals(Asn1Object asn1Object)
		{
			DerUtf8String that = asn1Object as DerUtf8String;
            return null != that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        protected override int Asn1GetHashCode()
        {
            return Arrays.GetHashCode(m_contents);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.Utf8String, m_contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.Utf8String, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new PrimitiveDerEncoding(tagClass, tagNo, m_contents);
        }

        internal static DerUtf8String CreatePrimitive(byte[] contents)
        {
            return new DerUtf8String(contents, false);
        }
    }
}
