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
                    throw new ArgumentException("failed to construct BMP string from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj));
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
            int remainingBytes = defIn.Remaining;
            if (0 != (remainingBytes & 1))
                throw new IOException("malformed BMPString encoding encountered");

            int length = remainingBytes / 2;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return new DerBmpString(string.Create(length, defIn, (str, defIn) =>
            {
                int stringPos = 0;

                Span<byte> buf = stackalloc byte[8];
                while (remainingBytes >= 8)
                {
                    if (Streams.ReadFully(defIn, buf) != 8)
                        throw new EndOfStreamException("EOF encountered in middle of BMPString");

                    str[stringPos] = (char)BinaryPrimitives.ReadUInt16BigEndian(buf[0..]);
                    str[stringPos + 1] = (char)BinaryPrimitives.ReadUInt16BigEndian(buf[2..]);
                    str[stringPos + 2] = (char)BinaryPrimitives.ReadUInt16BigEndian(buf[4..]);
                    str[stringPos + 3] = (char)BinaryPrimitives.ReadUInt16BigEndian(buf[6..]);
                    stringPos += 4;
                    remainingBytes -= 8;
                }
                if (remainingBytes > 0)
                {
                    if (Streams.ReadFully(defIn, buf) != remainingBytes)
                        throw new EndOfStreamException("EOF encountered in middle of BMPString");

                    int bufPos = 0;
                    do
                    {
                        int b1 = buf[bufPos++] << 8;
                        int b2 = buf[bufPos++] & 0xFF;
                        str[stringPos++] = (char)(b1 | b2);
                    }
                    while (bufPos < remainingBytes);
                }

                if (0 != defIn.Remaining || str.Length != stringPos)
                    throw new InvalidOperationException();
            }));
#else
            char[] str = new char[length];
            int stringPos = 0;

            byte[] buf = new byte[8];
            while (remainingBytes >= 8)
            {
                if (Streams.ReadFully(defIn, buf, 0, 8) != 8)
                    throw new EndOfStreamException("EOF encountered in middle of BMPString");

                str[stringPos    ] = (char)((buf[0] << 8) | (buf[1] & 0xFF));
                str[stringPos + 1] = (char)((buf[2] << 8) | (buf[3] & 0xFF));
                str[stringPos + 2] = (char)((buf[4] << 8) | (buf[5] & 0xFF));
                str[stringPos + 3] = (char)((buf[6] << 8) | (buf[7] & 0xFF));
                stringPos += 4;
                remainingBytes -= 8;
            }
            if (remainingBytes > 0)
            {
                if (Streams.ReadFully(defIn, buf, 0, remainingBytes) != remainingBytes)
                    throw new EndOfStreamException("EOF encountered in middle of BMPString");

                int bufPos = 0;
                do
                {
                    int b1 = buf[bufPos++] << 8;
                    int b2 = buf[bufPos++] & 0xFF;
                    str[stringPos++] = (char)(b1 | b2);
                }
                while (bufPos < remainingBytes);
            }

            if (0 != defIn.Remaining || str.Length != stringPos)
                throw new InvalidOperationException();

            return new DerBmpString(str);
#endif
        }

        private static DerBmpString CreatePrimitive(byte[] contents) => new DerBmpString(contents);
    }
}
