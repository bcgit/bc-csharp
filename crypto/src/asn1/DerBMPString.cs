using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers;
#endif
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /**
     * Der BMPString object.
     */
    public class DerBmpString
		: DerStringBase
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerBmpString), Asn1Tags.BmpString) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

		/**
         * return a BMP string from the given object.
         *
         * @param obj the object we want converted.
         * @exception ArgumentException if the object cannot be converted.
         */
        public static DerBmpString GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerBmpString derBmpString)
                return derBmpString;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerBmpString converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerBmpString)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct BMP string from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj));
        }

        /**
         * return a BMP string from a tagged object.
         *
         * @param taggedObject the tagged object holding the object we want
         * @param declaredExplicit true if the object is meant to be explicitly tagged false otherwise.
         * @exception ArgumentException if the tagged object cannot be converted.
         */
        public static DerBmpString GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerBmpString)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);
        }

        public static DerBmpString GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerBmpString existing)
                return existing;

            return null;
        }

        public static DerBmpString GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerBmpString)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        private readonly string m_str;

        internal DerBmpString(byte[] contents)
        {
			if (null == contents)
				throw new ArgumentNullException("contents");

            int byteLen = contents.Length;
            if (0 != (byteLen & 1))
                throw new ArgumentException("malformed BMPString encoding encountered", "contents");

            int charLen = byteLen / 2;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            m_str = string.Create(charLen, contents, (chars, bytes) =>
            {
                for (int i = 0; i < chars.Length; ++i)
                {
                    chars[i] = (char)((bytes[2 * i] << 8) | (bytes[2 * i + 1] & 0xff));
                }
            });
#else
            char[] cs = new char[charLen];

            for (int i = 0; i != charLen; i++)
            {
                cs[i] = (char)((contents[2 * i] << 8) | (contents[2 * i + 1] & 0xff));
            }

            m_str = new string(cs);
#endif
        }

#if !(NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
        internal DerBmpString(char[] str)
        {
            if (str == null)
                throw new ArgumentNullException("str");

            m_str = new string(str);
        }
#endif

        /**
         * basic constructor
         */
        public DerBmpString(string str)
        {
			if (str == null)
				throw new ArgumentNullException("str");

            m_str = str;
        }

        public override string GetString()
        {
            return m_str;
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            DerBmpString that = asn1Object as DerBmpString;
            return null != that
                && this.m_str.Equals(that.m_str);
        }

        protected override int Asn1GetHashCode()
        {
            return m_str.GetHashCode();
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.BmpString, GetContents());
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, GetContents());
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.BmpString, GetContents());
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new PrimitiveDerEncoding(tagClass, tagNo, GetContents());
        }

        private byte[] GetContents()
        {
            char[] c = m_str.ToCharArray();
            byte[] b = new byte[c.Length * 2];

            for (int i = 0; i != c.Length; i++)
            {
                b[2 * i] = (byte)(c[i] >> 8);
                b[2 * i + 1] = (byte)c[i];
            }

            return b;
        }

        internal static DerBmpString CreatePrimitive(byte[] contents)
        {
            return new DerBmpString(contents);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static DerBmpString CreatePrimitive<TState>(int length, TState state, SpanAction<char, TState> action)
        {
            return new DerBmpString(string.Create(length, state, action));
        }
#else
        internal static DerBmpString CreatePrimitive(char[] str)
        {
            // TODO[asn1] Asn1InputStream has a validator/converter that should be unified in this class somehow
            return new DerBmpString(str);
        }
#endif
    }
}
