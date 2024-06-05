using System;
using System.IO;
using System.Text;
using System.Threading;

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

        /// <summary>Implementation limit on the length of the contents octets for a Relative OID.</summary>
        /// <remarks>
        /// We adopt the same value used by OpenJDK for Object Identifier. In theory there is no limit on the length of
        /// the contents, or the number of subidentifiers, or the length of individual subidentifiers. In practice,
        /// supporting arbitrary lengths can lead to issues, e.g. denial-of-service attacks when attempting to convert a
        /// parsed value to its (decimal) string form.
        /// </remarks>
        private const int MaxContentsLength = 4096;
        private const int MaxIdentifierLength = MaxContentsLength * 4 - 1;

        public static Asn1RelativeOid FromContents(byte[] contents)
        {
            if (contents == null)
                throw new ArgumentNullException(nameof(contents));

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
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is Asn1RelativeOid converted)
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

        public static bool TryFromID(string identifier, out Asn1RelativeOid oid)
        {
            if (identifier == null)
                throw new ArgumentNullException(nameof(identifier));
            if (identifier.Length <= MaxIdentifierLength && IsValidIdentifier(identifier, from: 0))
            {
                byte[] contents = ParseIdentifier(identifier);
                if (contents.Length <= MaxContentsLength)
                {
                    oid = new Asn1RelativeOid(contents, identifier);
                    return true;
                }
            }

            oid = default;
            return false;
        }

        private const long LongLimit = (long.MaxValue >> 7) - 0x7F;

        private static readonly Asn1RelativeOid[] Cache = new Asn1RelativeOid[64];

        private readonly byte[] m_contents;
        private string m_identifier;

        public Asn1RelativeOid(string identifier)
        {
            CheckIdentifier(identifier);

            byte[] contents = ParseIdentifier(identifier);
            CheckContentsLength(contents.Length);

            m_contents = contents;
            m_identifier = identifier;
        }

        private Asn1RelativeOid(byte[] contents, string identifier)
        {
            m_contents = contents;
            m_identifier = identifier;
        }

        public virtual Asn1RelativeOid Branch(string branchID)
        {
            CheckIdentifier(branchID);

            byte[] branchContents = ParseIdentifier(branchID);
            CheckContentsLength(m_contents.Length + branchContents.Length);

            return new Asn1RelativeOid(
                contents: Arrays.Concatenate(m_contents, branchContents),
                identifier: GetID() + "." + branchID);
        }

        public string GetID()
        {
            return Objects.EnsureSingletonInitialized(ref m_identifier, m_contents, ParseContents);
        }

        [Obsolete("Use 'GetID' instead")]
        public string Id => GetID();

        public override string ToString() => GetID();

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return asn1Object is Asn1RelativeOid that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        protected override int Asn1GetHashCode()
        {
            return Arrays.GetHashCode(m_contents);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.RelativeOid, m_contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.RelativeOid, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new PrimitiveDerEncoding(tagClass, tagNo, m_contents);
        }

        internal static void CheckContentsLength(int contentsLength)
        {
            if (contentsLength > MaxContentsLength)
                throw new ArgumentException("exceeded relative OID contents length limit");
        }

        internal static void CheckIdentifier(string identifier)
        {
            if (identifier == null)
                throw new ArgumentNullException(nameof(identifier));
            if (identifier.Length > MaxIdentifierLength)
                throw new ArgumentException("exceeded relative OID contents length limit");
            if (!IsValidIdentifier(identifier, from: 0))
                throw new FormatException("string " + identifier + " not a valid relative OID");
        }

        internal static Asn1RelativeOid CreatePrimitive(byte[] contents, bool clone)
        {
            CheckContentsLength(contents.Length);

            uint index = (uint)Arrays.GetHashCode(contents);

            index ^= index >> 24;
            index ^= index >> 12;
            index ^= index >> 6;
            index &= 63;

            var originalEntry = Volatile.Read(ref Cache[index]);
            if (originalEntry != null && Arrays.AreEqual(contents, originalEntry.m_contents))
                return originalEntry;

            if (!IsValidContents(contents))
                throw new ArgumentException("invalid relative OID contents", nameof(contents));

            var newEntry = new Asn1RelativeOid(clone ? Arrays.Clone(contents) : contents, identifier: null);

            var exchangedEntry = Interlocked.CompareExchange(ref Cache[index], newEntry, originalEntry);
            if (exchangedEntry != originalEntry)
            {
                if (exchangedEntry != null && Arrays.AreEqual(contents, exchangedEntry.m_contents))
                    return exchangedEntry;
            }

            return newEntry;
        }

        internal static bool IsValidContents(byte[] contents)
        {
            if (contents.Length < 1)
                return false;

            bool subIDStart = true;
            for (int i = 0; i < contents.Length; ++i)
            {
                if (subIDStart && contents[i] == 0x80)
                    return false;

                subIDStart = (contents[i] & 0x80) == 0;
            }

            return subIDStart;
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

        internal static string ParseContents(byte[] contents)
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

        internal static byte[] ParseIdentifier(string identifier)
        {
            MemoryStream bOut = new MemoryStream();
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
            return bOut.ToArray();
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
    }
}
