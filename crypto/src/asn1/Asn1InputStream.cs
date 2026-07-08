using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>A general purpose ASN.1 decoder.</summary>
    /// <remarks>
    /// This class differs from the others in that it returns null after it has read the last object in the stream. If
    /// an ASN.1 Null is encountered a Der / BER Null object is returned.
    /// </remarks>
    public class Asn1InputStream
        : FilterStream
    {
        internal static void CheckLength(int length, int limit)
        {
            if (length > limit)
                throw new Asn1Exception("corrupted stream - out of bounds length found: " + length + " > " + limit);
        }

        internal static int DecrementDepth(int parentDepth)
        {
            if (parentDepth <= 0)
                throw new Asn1Exception("maximum nested construction level reached");
            return parentDepth - 1;
        }

        internal static int FindDepth()
        {
            if (Properties.TryGetInt32(Properties.Asn1MaxDepth, out int maxDepth))
                return System.Math.Max(0, maxDepth);

            return 64;
        }

        internal static int FindLimit(Stream input)
        {
            if (input is LimitedInputStream limited)
                return limited.Limit;

            if (input is Asn1InputStream asn1)
                return asn1.Limit;

            if (Streams.TryGetAvailable(input, out long available))
                return (int)System.Math.Min(Arrays.MaxLength, available);

            if (Properties.TryGetInt32(Properties.Asn1MaxLimit, out int maxLimit))
                return System.Math.Max(0, maxLimit);

            return Arrays.MaxLength;
        }

        private readonly int m_depth;
        private readonly int m_limit;
        private readonly bool m_leaveOpen;
        private readonly byte[] m_tmp;

        /// <summary>Create an Asn1InputStream based on the input byte array.</summary>
        /// <remarks>
        /// The length of DER objects in the stream is automatically limited to the length of the input array.
        /// </remarks>
        /// <param name="input">Array containing ASN.1 encoded data.</param>
        public Asn1InputStream(byte[] input)
            : this(new MemoryStream(input, false), input.Length)
        {
        }

        public Asn1InputStream(Stream input)
            : this(input, FindLimit(input))
        {
        }

        public Asn1InputStream(Stream input, bool leaveOpen)
            : this(input, FindLimit(input), leaveOpen)
        {
        }

        /// <summary>Create an Asn1InputStream where no DER object will be longer than limit.</summary>
        /// <param name="input">Stream containing ASN.1 encoded data.</param>
        /// <param name="limit">Maximum size of a DER encoded object.</param>
        public Asn1InputStream(Stream input, int limit)
            : this(input, limit, false)
        {
        }

        public Asn1InputStream(Stream input, int limit, bool leaveOpen)
            : this(input, FindDepth(), limit, leaveOpen, tmp: new byte[16])
        {
        }

        internal Asn1InputStream(Stream input, int depth, int limit, bool leaveOpen, byte[] tmp)
            : base(input)
        {
            if (!input.CanRead)
                throw new ArgumentException("Expected stream to be readable", nameof(input));

            m_depth = depth;
            m_limit = limit;
            m_leaveOpen = leaveOpen;
            m_tmp = tmp;
        }

        private Asn1InputStream CreateSubStream(Stream sub, int limit) =>
            new Asn1InputStream(sub, DecrementDepth(m_depth), limit, leaveOpen: true, m_tmp);

        public int Limit => m_limit;

        protected override void Dispose(bool disposing)
        {
            if (m_leaveOpen)
            {
                base.Detach(disposing);
            }
            else
            {
                base.Dispose(disposing);
            }
        }

        /// <summary>Build an object given its tag and the number of bytes to construct it from.</summary>
        private Asn1Object BuildObject(int tagHdr, int tagNo, int length)
        {
            // TODO[asn1] Special-case zero length first?

            CheckLength(length, m_limit);
            DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(s, length, limit: length);

            if (0 == (tagHdr & Asn1Tags.Flags))
                return CreatePrimitiveDerObject(tagNo, defIn, m_tmp);

            int tagClass = tagHdr & Asn1Tags.Private;
            if (0 != tagClass)
            {
                bool isConstructed = (tagHdr & Asn1Tags.Constructed) != 0;
                return ReadTaggedObjectDL(tagClass, tagNo, isConstructed, defIn);
            }

            switch (tagNo)
            {
            case Asn1Tags.BitString:
                return BuildConstructedBitString(ReadVector(defIn));
            case Asn1Tags.OctetString:
                return BuildConstructedOctetString(ReadVector(defIn));
            case Asn1Tags.Sequence:
                return DLSequence.FromVector(ReadVector(defIn));
            case Asn1Tags.Set:
                return DLSet.FromVector(ReadVector(defIn));
            case Asn1Tags.External:
                return DLSequence.FromVector(ReadVector(defIn)).ToAsn1External();
            default:
                throw new IOException("unknown tag " + tagNo + " encountered");
            }
        }

        internal Asn1Object ReadTaggedObjectDL(int tagClass, int tagNo, bool constructed, DefiniteLengthInputStream defIn)
        {
            if (!constructed)
            {
                byte[] contentsOctets = defIn.ToArray();
                return Asn1TaggedObject.CreatePrimitive(tagClass, tagNo, contentsOctets);
            }

            Asn1EncodableVector contentsElements = ReadVector(defIn);
            return Asn1TaggedObject.CreateConstructedDL(tagClass, tagNo, contentsElements);
        }

        private Asn1EncodableVector ReadVector()
        {
            Asn1Object o = ReadObject();
            if (null == o)
                return new Asn1EncodableVector(0);

            Asn1EncodableVector v = new Asn1EncodableVector();
            do
            {
                v.Add(o);
            }
            while ((o = ReadObject()) != null);
            return v;
        }

        private Asn1EncodableVector ReadVector(DefiniteLengthInputStream defIn)
        {
            int remaining = defIn.Remaining;
            if (remaining < 1)
                return new Asn1EncodableVector(0);

            using (var sub = CreateSubStream(defIn, remaining))
            {
                return sub.ReadVector();
            }
        }

        public Asn1Object ReadObject()
        {
            int tagHdr = s.ReadByte();
            if (tagHdr <= 0)
            {
                if (tagHdr == 0)
                    throw new IOException("unexpected end-of-contents marker");

                return null;
            }

            int tagNo = ReadTagNumber(s, tagHdr);
            int length = ReadLength(s);

            if (length >= 0)
            {
                // definite-length
                try
                {
                    return BuildObject(tagHdr, tagNo, length);
                }
                catch (ArgumentException e)
                {
                    throw new Asn1Exception("corrupted stream detected", e);
                }
                catch (InvalidOperationException e)
                {
                    throw new Asn1Exception("corrupted stream detected", e);
                }
                catch (IndexOutOfRangeException e)
                {
                    throw new Asn1Exception("corrupted stream detected", e);
                }
            }

            // indefinite-length

            if (0 == (tagHdr & Asn1Tags.Constructed))
                throw new IOException("indefinite-length primitive encoding encountered");

            IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(s, m_limit);
            Asn1StreamParser sp = Asn1StreamParser.CreateSubParser(indIn, m_depth, m_limit, m_tmp);

            int tagClass = tagHdr & Asn1Tags.Private;
            if (0 != tagClass)
                return sp.LoadTaggedIL(tagClass, tagNo);

            switch (tagNo)
            {
            case Asn1Tags.BitString:
                return BerBitStringParser.Parse(sp);
#pragma warning disable CS0618 // Type or member is obsolete
            case Asn1Tags.OctetString:
                return BerOctetStringParser.Parse(sp);
            case Asn1Tags.Sequence:
                return BerSequenceParser.Parse(sp);
            case Asn1Tags.Set:
                return BerSetParser.Parse(sp);
#pragma warning restore CS0618 // Type or member is obsolete
            case Asn1Tags.External:
                // TODO[asn1] BerExternalParser
                return DerExternalParser.Parse(sp);
            default:
                throw new IOException("unknown BER object encountered");
            }
        }

        private static DLBitString BuildConstructedBitString(Asn1EncodableVector contentsElements)
        {
            DerBitString[] bitStrings = new DerBitString[contentsElements.Count];

            for (int i = 0; i != bitStrings.Length; i++)
            {
                if (!(contentsElements[i] is DerBitString bitString))
                    throw new Asn1Exception("unknown object encountered in constructed BIT STRING: "
                        + Platform.GetTypeName(contentsElements[i]));

                bitStrings[i] = bitString;
            }

            return new DLBitString(BerBitString.FlattenBitStrings(bitStrings), false);
        }

        private static DerOctetString BuildConstructedOctetString(Asn1EncodableVector contentsElements)
        {
            Asn1OctetString[] octetStrings = new Asn1OctetString[contentsElements.Count];

            for (int i = 0; i != octetStrings.Length; i++)
            {
                if (!(contentsElements[i] is Asn1OctetString octetString))
                    throw new Asn1Exception("unknown object encountered in constructed OCTET STRING: "
                        + Platform.GetTypeName(contentsElements[i]));

                octetStrings[i] = octetString;
            }

            // Note: No DLOctetString available
            return DerOctetString.WithContents(BerOctetString.FlattenOctetStrings(octetStrings));
        }

        internal static int ReadTagNumber(Stream s, int tagHdr)
        {
            int tagNo = tagHdr & 0x1f;

            //
            // with tagged object tag number is bottom 5 bits, or stored at the start of the content
            //
            if (tagNo == 0x1f)
            {
                int b = s.ReadByte();
                if (b < 31)
                {
                    if (b < 0)
                        throw new EndOfStreamException("EOF found inside tag value.");

                    throw new IOException("corrupted stream - high tag number < 31 found");
                }

                tagNo = b & 0x7f;

                // X.690-0207 8.1.2.4.2
                // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
                if (0 == tagNo)
                    throw new IOException("corrupted stream - invalid high tag number found");

                while ((b & 0x80) != 0)
                {
                    if (((uint)tagNo >> 24) != 0U)
                        throw new IOException("Tag number more than 31 bits");

                    tagNo <<= 7;

                    b = s.ReadByte();
                    if (b < 0)
                        throw new EndOfStreamException("EOF found inside tag value.");

                    tagNo |= b & 0x7f;
                }
            }

            return tagNo;
        }

        internal static int ReadLength(Stream s)
        {
            int length = s.ReadByte();
            if (0U == ((uint)length >> 7))
            {
                // definite-length short form 
                return length;
            }
            if (0x80 == length)
            {
                // indefinite-length
                return -1;
            }
            if (length < 0)
            {
                throw new EndOfStreamException("EOF found when length expected");
            }
            if (0xFF == length)
            {
                throw new IOException("invalid long form definite-length 0xFF");
            }

            int octetsCount = length & 0x7F, octetsPos = 0;

            length = 0;
            do
            {
                int octet = s.ReadByte();
                if (octet < 0)
                    throw new EndOfStreamException("EOF found reading length");

                if (((uint)length >> 23) != 0U)
                    throw new IOException("long form definite-length more than 31 bits");

                length = (length << 8) + octet;
            }
            while (++octetsPos < octetsCount);

            return length;
        }

        internal static Asn1Object CreatePrimitiveDerObject(int tagNo, DefiniteLengthInputStream defIn, byte[] tmp)
        {
            switch (tagNo)
            {
            case Asn1Tags.BmpString:
                return DerBmpString.CreatePrimitive(defIn);
            case Asn1Tags.Boolean:
                return DerBoolean.CreatePrimitive(defIn);
            case Asn1Tags.Enumerated:
                return DerEnumerated.CreatePrimitive(defIn);
            case Asn1Tags.Null:
                return Asn1Null.CreatePrimitive(defIn);
            case Asn1Tags.ObjectIdentifier:
                return DerObjectIdentifier.CreatePrimitive(defIn, tmp);
            case Asn1Tags.RelativeOid:
                return Asn1RelativeOid.CreatePrimitive(defIn, tmp);
            }

            byte[] bytes = defIn.ToArray();

            switch (tagNo)
            {
            case Asn1Tags.BitString:
                return DerBitString.CreatePrimitive(bytes);
            case Asn1Tags.GeneralizedTime:
                return Asn1GeneralizedTime.CreatePrimitive(bytes);
            case Asn1Tags.GeneralString:
                return DerGeneralString.CreatePrimitive(bytes);
            case Asn1Tags.GraphicString:
                return DerGraphicString.CreatePrimitive(bytes);
            case Asn1Tags.IA5String:
                return DerIA5String.CreatePrimitive(bytes);
            case Asn1Tags.Integer:
                return DerInteger.CreatePrimitive(bytes);
            case Asn1Tags.NumericString:
                return DerNumericString.CreatePrimitive(bytes);
            case Asn1Tags.ObjectDescriptor:
                return Asn1ObjectDescriptor.CreatePrimitive(bytes);
            case Asn1Tags.OctetString:
                return Asn1OctetString.CreatePrimitive(bytes);
            case Asn1Tags.PrintableString:
                return DerPrintableString.CreatePrimitive(bytes);
            case Asn1Tags.T61String:
                return DerT61String.CreatePrimitive(bytes);
            case Asn1Tags.UniversalString:
                return DerUniversalString.CreatePrimitive(bytes);
            case Asn1Tags.UtcTime:
                return Asn1UtcTime.CreatePrimitive(bytes);
            case Asn1Tags.Utf8String:
                return DerUtf8String.CreatePrimitive(bytes);
            case Asn1Tags.VideotexString:
                return DerVideotexString.CreatePrimitive(bytes);
            case Asn1Tags.VisibleString:
                return DerVisibleString.CreatePrimitive(bytes);

            case Asn1Tags.Real:
            case Asn1Tags.EmbeddedPdv:
            case Asn1Tags.Time:
            case Asn1Tags.UnrestrictedString:
            case Asn1Tags.Date:
            case Asn1Tags.TimeOfDay:
            case Asn1Tags.DateTime:
            case Asn1Tags.Duration:
            case Asn1Tags.ObjectIdentifierIri:
            case Asn1Tags.RelativeOidIri:
                throw new IOException("unsupported tag " + tagNo + " encountered");
            default:
                throw new IOException("unknown tag " + tagNo + " encountered");
            }
        }
    }
}
