using System;
using System.IO;
using System.Text;
using System.Threading;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class DerObjectIdentifier
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerObjectIdentifier), Asn1Tags.ObjectIdentifier) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets(), false);
            }
        }

        /// <summary>Implementation limit on the length of the contents octets for an Object Identifier.</summary>
        /// <remarks>
        /// We adopt the same value used by OpenJDK. In theory there is no limit on the length of the contents, or the
        /// number of subidentifiers, or the length of individual subidentifiers. In practice, supporting arbitrary
        /// lengths can lead to issues, e.g. denial-of-service attacks when attempting to convert a parsed value to its
        /// (decimal) string form.
        /// </remarks>
        private const int MaxContentsLength = 4096;
        private const int MaxIdentifierLength = MaxContentsLength * 4 + 1;

        public static DerObjectIdentifier FromContents(byte[] contents)
        {
            if (contents == null)
                throw new ArgumentNullException(nameof(contents));

            return CreatePrimitive(contents, true);
        }

        /**
         * return an OID from the passed in object
         *
         * @exception ArgumentException if the object cannot be converted.
         */
        public static DerObjectIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerObjectIdentifier derObjectIdentifier)
                return derObjectIdentifier;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerObjectIdentifier converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerObjectIdentifier)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct object identifier from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
        }

        public static DerObjectIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            /*
             * TODO[api] This block is for backward compatibility, but should be removed.
             * 
             * - see https://github.com/bcgit/bc-java/issues/1015
             */
            if (!declaredExplicit && !taggedObject.IsParsed() && taggedObject.HasContextTag())
            {
                Asn1Object baseObject = taggedObject.GetBaseObject().ToAsn1Object();
                if (!(baseObject is DerObjectIdentifier))
                    return FromContents(Asn1OctetString.GetInstance(baseObject).GetOctets());
            }

            return (DerObjectIdentifier)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
        }

        public static DerObjectIdentifier GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerObjectIdentifier existing)
                return existing;

            return null;
        }

        public static DerObjectIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerObjectIdentifier)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        public static bool TryFromID(string identifier, out DerObjectIdentifier oid)
        {
            if (identifier == null)
                throw new ArgumentNullException(nameof(identifier));
            if (identifier.Length <= MaxIdentifierLength && IsValidIdentifier(identifier))
            {
                byte[] contents = ParseIdentifier(identifier);
                if (contents.Length <= MaxContentsLength)
                {
                    oid = new DerObjectIdentifier(contents, identifier);
                    return true;
                }
            }

            oid = default;
            return false;
        }

        private const long LongLimit = (long.MaxValue >> 7) - 0x7F;

        private static readonly DerObjectIdentifier[] Cache = new DerObjectIdentifier[1024];

        private readonly byte[] m_contents;
        private string m_identifier;

        public DerObjectIdentifier(string identifier)
        {
            CheckIdentifier(identifier);

            byte[] contents = ParseIdentifier(identifier);
            CheckContentsLength(contents.Length);

            m_contents = contents;
            m_identifier = identifier;
        }

        private DerObjectIdentifier(byte[] contents, string identifier)
        {
            m_contents = contents;
            m_identifier = identifier;
        }

        public virtual DerObjectIdentifier Branch(string branchID)
        {
            Asn1RelativeOid.CheckIdentifier(branchID);

            byte[] branchContents = Asn1RelativeOid.ParseIdentifier(branchID);
            CheckContentsLength(m_contents.Length + branchContents.Length);

            return new DerObjectIdentifier(
                contents: Arrays.Concatenate(m_contents, branchContents),
                identifier: GetID() + "." + branchID);
        }

        public string GetID()
        {
            return Objects.EnsureSingletonInitialized(ref m_identifier, m_contents, ParseContents);
        }

        // TODO[api]
        //[Obsolete("Use 'GetID' instead")]
        public string Id => GetID();

        /**
         * Return  true if this oid is an extension of the passed in branch, stem.
         * @param stem the arc or branch that is a possible parent.
         * @return  true if the branch is on the passed in stem, false otherwise.
         */
        public virtual bool On(DerObjectIdentifier stem)
        {
            byte[] contents = m_contents, stemContents = stem.m_contents;
            int stemLength = stemContents.Length;

            return contents.Length > stemLength
                && Arrays.AreEqual(contents, 0, stemLength, stemContents, 0, stemLength);
        }

        public override string ToString() => GetID();

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return asn1Object is DerObjectIdentifier that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        protected override int Asn1GetHashCode()
        {
            return Arrays.GetHashCode(m_contents);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.ObjectIdentifier, m_contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.ObjectIdentifier, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new PrimitiveDerEncoding(tagClass, tagNo, m_contents);
        }

        internal static void CheckContentsLength(int contentsLength)
        {
            if (contentsLength > MaxContentsLength)
                throw new ArgumentException("exceeded OID contents length limit");
        }

        internal static void CheckIdentifier(string identifier)
        {
            if (identifier == null)
                throw new ArgumentNullException(nameof(identifier));
            if (identifier.Length > MaxIdentifierLength)
                throw new ArgumentException("exceeded OID contents length limit");
            if (!IsValidIdentifier(identifier))
                throw new FormatException("string " + identifier + " not a valid OID");
        }

        internal static DerObjectIdentifier CreatePrimitive(byte[] contents, bool clone)
        {
            CheckContentsLength(contents.Length);

            uint index = (uint)Arrays.GetHashCode(contents);

            index ^= index >> 20;
            index ^= index >> 10;
            index &= 1023;

            var originalEntry = Volatile.Read(ref Cache[index]);
            if (originalEntry != null && Arrays.AreEqual(contents, originalEntry.m_contents))
                return originalEntry;

            if (!Asn1RelativeOid.IsValidContents(contents))
                throw new ArgumentException("invalid OID contents", nameof(contents));

            var newEntry = new DerObjectIdentifier(clone ? Arrays.Clone(contents) : contents, identifier: null);

            var exchangedEntry = Interlocked.CompareExchange(ref Cache[index], newEntry, originalEntry);
            if (exchangedEntry != originalEntry)
            {
                if (exchangedEntry != null && Arrays.AreEqual(contents, exchangedEntry.m_contents))
                    return exchangedEntry;
            }

            return newEntry;
        }

        private static bool IsValidIdentifier(string identifier)
        {
            if (identifier.Length < 3 || identifier[1] != '.')
                return false;

            char first = identifier[0];
            if (first < '0' || first > '2')
                return false;

            if (!Asn1RelativeOid.IsValidIdentifier(identifier, from: 2))
                return false;

            if (first == '2')
                return true;

            if (identifier.Length == 3 || identifier[3] == '.')
                return true;

            if (identifier.Length == 4 || identifier[4] == '.')
                return identifier[2] < '4';

            return false;
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
                            if (value < 40)
                            {
                                objId.Append('0');
                            }
                            else if (value < 80)
                            {
                                objId.Append('1');
                                value -= 40;
                            }
                            else
                            {
                                objId.Append('2');
                                value -= 80;
                            }
                            first = false;
                        }

                        objId.Append('.');
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
                            objId.Append('2');
                            bigValue = bigValue.Subtract(BigInteger.ValueOf(80));
                            first = false;
                        }

                        objId.Append('.');
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

        private static byte[] ParseIdentifier(string identifier)
        {
            MemoryStream bOut = new MemoryStream();
            OidTokenizer tok = new OidTokenizer(identifier);

            string token = tok.NextToken();
            int first = int.Parse(token) * 40;

            token = tok.NextToken();
            if (token.Length <= 18)
            {
                Asn1RelativeOid.WriteField(bOut, first + long.Parse(token));
            }
            else
            {
                Asn1RelativeOid.WriteField(bOut, new BigInteger(token).Add(BigInteger.ValueOf(first)));
            }

            while (tok.HasMoreTokens)
            {
                token = tok.NextToken();
                if (token.Length <= 18)
                {
                    Asn1RelativeOid.WriteField(bOut, long.Parse(token));
                }
                else
                {
                    Asn1RelativeOid.WriteField(bOut, new BigInteger(token));
                }
            }

            return bOut.ToArray();
        }
    }
}
