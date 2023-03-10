using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class Asn1RelativeOid
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(Asn1RelativeOid), Asn1Tags.RelativeOid) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets(), false);
            }
        }

        public static Asn1RelativeOid FromContents(byte[] contents)
        {
            return CreatePrimitive(contents, true);
        }

        public static Asn1RelativeOid GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is Asn1RelativeOid asn1RelativeOid)
                return asn1RelativeOid;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                Asn1Object asn1Object = asn1Convertible.ToAsn1Object();
                if (asn1Object is Asn1RelativeOid converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (Asn1RelativeOid)FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct relative OID from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
        }

        public static Asn1RelativeOid GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (Asn1RelativeOid)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
        }

        private const long LongLimit = (long.MaxValue >> 7) - 0x7F;

        private readonly string identifier;
        private byte[] contents;

        public Asn1RelativeOid(string identifier)
        {
            if (identifier == null)
                throw new ArgumentNullException("identifier");
            if (!IsValidIdentifier(identifier, 0))
                throw new FormatException("string " + identifier + " not a relative OID");

            this.identifier = identifier;
        }

        private Asn1RelativeOid(Asn1RelativeOid oid, string branchID)
        {
            if (!IsValidIdentifier(branchID, 0))
                throw new FormatException("string " + branchID + " not a valid relative OID branch");

            this.identifier = oid.Id + "." + branchID;
        }

        private Asn1RelativeOid(byte[] contents, bool clone)
        {
            this.identifier = ParseContents(contents);
            this.contents = clone ? Arrays.Clone(contents) : contents;
        }

        public virtual Asn1RelativeOid Branch(string branchID)
        {
            return new Asn1RelativeOid(this, branchID);
        }

        public string Id
        {
            get { return identifier; }
        }

        public override string ToString()
        {
            return identifier;
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            Asn1RelativeOid that = asn1Object as Asn1RelativeOid;
            return null != that
                && this.identifier == that.identifier;
        }

        protected override int Asn1GetHashCode()
        {
            return identifier.GetHashCode();
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.RelativeOid, GetContents());
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, GetContents());
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.RelativeOid, GetContents());
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new PrimitiveDerEncoding(tagClass, tagNo, GetContents());
        }

        private void DoOutput(MemoryStream bOut)
        {
            OidTokenizer tok = new OidTokenizer(identifier);
            while (tok.HasMoreTokens)
            {
                string token = tok.NextToken();
                if (token.Length <= 18)
                {
                    WriteField(bOut, long.Parse(token));
                }
                else
                {
                    WriteField(bOut, new BigInteger(token));
                }
            }
        }

        private byte[] GetContents()
        {
            lock (this)
            {
                if (contents == null)
                {
                    MemoryStream bOut = new MemoryStream();
                    DoOutput(bOut);
                    contents = bOut.ToArray();
                }

                return contents;
            }
        }

        internal static Asn1RelativeOid CreatePrimitive(byte[] contents, bool clone)
        {
            return new Asn1RelativeOid(contents, clone);
        }

        internal static bool IsValidIdentifier(string identifier, int from)
        {
            int digitCount = 0;

            int pos = identifier.Length;
            while (--pos >= from)
            {
                char ch = identifier[pos];

                if (ch == '.')
                {
                    if (0 == digitCount || (digitCount > 1 && identifier[pos + 1] == '0'))
                        return false;

                    digitCount = 0;
                }
                else if ('0' <= ch && ch <= '9')
                {
                    ++digitCount;
                }
                else
                {
                    return false;
                }
            }

            if (0 == digitCount || (digitCount > 1 && identifier[pos + 1] == '0'))
                return false;

            return true;
        }

        internal static void WriteField(Stream outputStream, long fieldValue)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> result = stackalloc byte[9];
#else
            byte[] result = new byte[9];
#endif
            int pos = 8;
            result[pos] = (byte)((int)fieldValue & 0x7F);
            while (fieldValue >= (1L << 7))
            {
                fieldValue >>= 7;
                result[--pos] = (byte)((int)fieldValue | 0x80);
            }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            outputStream.Write(result[pos..]);
#else
            outputStream.Write(result, pos, 9 - pos);
#endif
        }

        internal static void WriteField(Stream outputStream, BigInteger fieldValue)
        {
            int byteCount = (fieldValue.BitLength + 6) / 7;
            if (byteCount == 0)
            {
                outputStream.WriteByte(0);
            }
            else
            {
                BigInteger tmpValue = fieldValue;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<byte> tmp = byteCount <= 16
                    ? stackalloc byte[byteCount]
                    : new byte[byteCount];
#else
                byte[] tmp = new byte[byteCount];
#endif
                for (int i = byteCount - 1; i >= 0; i--)
                {
                    tmp[i] = (byte)(tmpValue.IntValue | 0x80);
                    tmpValue = tmpValue.ShiftRight(7);
                }
                tmp[byteCount - 1] &= 0x7F;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                outputStream.Write(tmp);
#else
                outputStream.Write(tmp, 0, tmp.Length);
#endif
            }
        }

        private static string ParseContents(byte[] contents)
        {
            StringBuilder objId = new StringBuilder();
            long value = 0;
            BigInteger bigValue = null;
            bool first = true;

            for (int i = 0; i != contents.Length; i++)
            {
                int b = contents[i];

                if (value <= LongLimit)
                {
                    value += b & 0x7F;
                    if ((b & 0x80) == 0)
                    {
                        if (first)
                        {
                            first = false;
                        }
                        else
                        {
                            objId.Append('.');
                        }

                        objId.Append(value);
                        value = 0;
                    }
                    else
                    {
                        value <<= 7;
                    }
                }
                else
                {
                    if (bigValue == null)
                    {
                        bigValue = BigInteger.ValueOf(value);
                    }
                    bigValue = bigValue.Or(BigInteger.ValueOf(b & 0x7F));
                    if ((b & 0x80) == 0)
                    {
                        if (first)
                        {
                            first = false;
                        }
                        else
                        {
                            objId.Append('.');
                        }

                        objId.Append(bigValue);
                        bigValue = null;
                        value = 0;
                    }
                    else
                    {
                        bigValue = bigValue.ShiftLeft(7);
                    }
                }
            }

            return objId.ToString();
        }
    }
}
