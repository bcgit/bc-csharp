using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers.Binary;
#endif
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>DER BMPString object.</summary>
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
                    throw new ArgumentException("failed to construct BMP string from byte[]", nameof(obj), e);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

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
                throw new ArgumentNullException(nameof(contents));

            int byteLen = contents.Length;
            if (0 != (byteLen & 1))
                throw new ArgumentException("malformed BMPString encoding encountered", nameof(contents));

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
            m_str = new string(str ?? throw new ArgumentNullException(nameof(str)));
        }
#endif

        public DerBmpString(string str)
        {
            m_str = str ?? throw new ArgumentNullException(nameof(str));
        }

        public override string GetString() => m_str;

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

        internal static DerBmpString CreatePrimitive(DefiniteLengthInputStream defIn)
        {
            if (0 != (defIn.Remaining & 1))
                throw new IOException("malformed BMPString encoding encountered");

            // NOTE: read through ToArray, which grows its buffer as bytes actually arrive, so a crafted (invalid) small
            // header can't cause a large allocation (GBs) before any content is actually read.
            return CreatePrimitive(defIn.ToArray());
        }

        private static DerBmpString CreatePrimitive(byte[] contents) => new DerBmpString(contents);
    }
}
