using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 OBJECT IDENTIFIER type.</summary>
    public class DerObjectIdentifier
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerObjectIdentifier), Asn1Tags.ObjectIdentifier) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets(), clone: false);
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

        /// <summary>Create an object identifier from the contents octets of its encoding.</summary>
        /// <param name="contents">The contents octets.</param>
        /// <returns>The object identifier.</returns>
        public static DerObjectIdentifier FromContents(byte[] contents) =>
            CreatePrimitive(contents ?? throw new ArgumentNullException(nameof(contents)), clone: true);

        /// <summary>Return an <see cref="DerObjectIdentifier"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DerObjectIdentifier"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DerObjectIdentifier"/>, or null if <paramref name="obj"/> is null.</returns>
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
                    throw new ArgumentException("failed to construct object identifier from byte[]", nameof(obj), e);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        /// <summary>Return an <see cref="DerObjectIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DerObjectIdentifier"/>.</returns>
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

            return (DerObjectIdentifier)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);
        }

        /// <summary>Return an <see cref="DerObjectIdentifier"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="DerObjectIdentifier"/>, or null if <paramref name="element"/> is null.</returns>
        public static DerObjectIdentifier GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerObjectIdentifier existing)
                return existing;

            return null;
        }

        /// <summary>Return an <see cref="DerObjectIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DerObjectIdentifier"/>.</returns>
        public static DerObjectIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerObjectIdentifier)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        /// <summary>Try to create an object identifier from its string form.</summary>
        /// <param name="identifier">The dotted-decimal string.</param>
        /// <param name="oid">On success, the object identifier.</param>
        /// <returns>true if the string was valid, false otherwise.</returns>
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

        /// <summary>Create a new <see cref="DerObjectIdentifier"/>.</summary>
        /// <param name="identifier">The identifier.</param>
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

        /// <summary>Create an object identifier by appending a branch to this one.</summary>
        /// <param name="branchID">The dotted-decimal branch to append.</param>
        /// <returns>The new object identifier.</returns>
        public virtual DerObjectIdentifier Branch(string branchID)
        {
            Asn1RelativeOid.CheckIdentifier(branchID);

            byte[] contents;
            if (branchID.Length <= 2)
            {
                CheckContentsLength(m_contents.Length + 1);
                int subID = branchID[0] - '0';
                if (branchID.Length == 2)
                {
                    subID *= 10;
                    subID += branchID[1] - '0';
                }

                contents = Arrays.Append(m_contents, (byte)subID);
            }
            else
            {
                byte[] branchContents = Asn1RelativeOid.ParseIdentifier(branchID);
                CheckContentsLength(m_contents.Length + branchContents.Length);

                contents = Arrays.Concatenate(m_contents, branchContents);
            }

            string rootID = GetID();
            string identifier = string.Concat(rootID, ".", branchID);

            return new DerObjectIdentifier(contents, identifier);
        }

        /// <summary>Return the ID.</summary>
        public string GetID()
        {
            return Objects.EnsureSingletonInitialized(ref m_identifier, m_contents, ParseContents);
        }

        /// <summary>Gets the id.</summary>
        // TODO[api]
        //[Obsolete("Use 'GetID' instead")]
        public string Id => GetID();

        /// <summary>Return  true if this oid is an extension of the passed in branch, stem.</summary>
        /// <param name="stem">The arc or branch that is a possible parent.</param>
        /// <returns>true if the branch is on the passed in stem, false otherwise.</returns>
        public virtual bool On(DerObjectIdentifier stem)
        {
            byte[] contents = m_contents, stemContents = stem.m_contents;
            int stemLength = stemContents.Length;

            return contents.Length > stemLength
                && Arrays.AreEqual(contents, 0, stemLength, stemContents, 0, stemLength);
        }

        /// <inheritdoc/>
        public override string ToString() => GetID();

        /// <inheritdoc/>
        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return asn1Object is DerObjectIdentifier that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        /// <inheritdoc/>
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

        private static int CheckContentsLength(int contentsLength)
        {
            if (contentsLength > MaxContentsLength)
                throw new ArgumentException("exceeded OID contents length limit");
            return contentsLength;
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

        private static bool ContentsEquals(byte[] a, byte[] b, int bLen) => Arrays.AreEqual(a, 0, a.Length, b, 0, bLen);

        internal static DerObjectIdentifier CreatePrimitive(DefiniteLengthInputStream defIn, byte[] tmp)
        {
            int contentsLength = CheckContentsLength(defIn.Remaining);

            bool useTmp = contentsLength <= tmp.Length;
            if (useTmp)
            {
                defIn.ReadAllIntoByteArray(tmp);
            }
            else
            {
                tmp = defIn.ToArray();
            }

            return CreatePrimitive(contents: tmp, contentsLength, clone: useTmp);
        }

        private static DerObjectIdentifier CreatePrimitive(byte[] contents, bool clone) =>
            CreatePrimitive(contents, CheckContentsLength(contents.Length), clone);

        private static DerObjectIdentifier CreatePrimitive(byte[] contents, int contentsLength, bool clone)
        {
            Debug.Assert(clone || contents.Length == contentsLength);

            uint index = (uint)Arrays.GetHashCode(contents, 0, contentsLength);

            index ^= index >> 20;
            index ^= index >> 10;
            index &= 1023;

            var originalEntry = Volatile.Read(ref Cache[index]);
            if (originalEntry != null && ContentsEquals(originalEntry.m_contents, contents, contentsLength))
                return originalEntry;

            if (!Asn1RelativeOid.IsValidContents(contents, contentsLength))
                throw new ArgumentException("invalid OID contents", nameof(contents));

            var newContents = clone ? Arrays.CopySegment(contents, 0, contentsLength) : contents;
            var newEntry = new DerObjectIdentifier(newContents, identifier: null);

            var exchangedEntry = Interlocked.CompareExchange(ref Cache[index], newEntry, originalEntry);
            if (exchangedEntry != originalEntry)
            {
                if (exchangedEntry != null && ContentsEquals(exchangedEntry.m_contents, contents, contentsLength))
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

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static byte[] ParseIdentifier(string identifier)
        {
            int contentsLimit = identifier.Length / 2;
            Span<byte> buf = contentsLimit <= 1024
                ? stackalloc byte[contentsLimit]
                : new byte[contentsLimit];

            uint extra = (uint)(identifier[0] - '0') * 40U;

            int i = 2, j = 2, off = 0;
            while (++j < identifier.Length)
            {
                if (identifier[j] == '.')
                {
                    WriteField(buf, ref off, identifier, i, j, extra);
                    extra = 0U;
                    i = j + 1;
                    j = i;
                }
            }
            WriteField(buf, ref off, identifier, i, j, extra);

            return buf[..off].ToArray();
        }

        private static void WriteField(Span<byte> buf, ref int off, string identifier, int from, int to, uint extra)
        {
            int length = to - from;
            if (length <= 19)
            {
                var fieldValue = ulong.Parse(identifier.AsSpan(from, length)) + extra;
                Asn1RelativeOid.WriteField(buf, ref off, fieldValue);
            }
            else
            {
                var fieldValue = new BigInteger(identifier.Substring(from, length)).Add(BigInteger.ValueOf(extra));
                Asn1RelativeOid.WriteField(buf, ref off, fieldValue);
            }
        }
#else
        private static byte[] ParseIdentifier(string identifier)
        {
            int contentsLimit = identifier.Length / 2;
            MemoryStream buf = new MemoryStream(capacity: contentsLimit);

            uint extra = (uint)(identifier[0] - '0') * 40U;

            int i = 2, j = 2;
            while (++j < identifier.Length)
            {
                if (identifier[j] == '.')
                {
                    WriteField(buf, identifier, i, j, extra);
                    extra = 0U;
                    i = j + 1;
                    j = i;
                }
            }
            WriteField(buf, identifier, i, j, extra);

            return buf.ToArray();
        }

        private static void WriteField(MemoryStream buf, string identifier, int from, int to, uint extra)
        {
            string token = identifier.Substring(from, to - from);
            if (token.Length <= 19)
            {
                var fieldValue = ulong.Parse(token) + extra;
                Asn1RelativeOid.WriteField(buf, fieldValue);
            }
            else
            {
                var fieldValue = new BigInteger(token).Add(BigInteger.ValueOf(extra));
                Asn1RelativeOid.WriteField(buf, fieldValue);
            }
        }
#endif
    }
}
