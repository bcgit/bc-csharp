using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers.Binary;
#endif
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    /**
     * a general purpose ASN.1 decoder - note: this class differs from the
     * others in that it returns null after it has read the last object in
     * the stream. If an ASN.1 Null is encountered a Der/BER Null object is
     * returned.
     */
    public class Asn1InputStream
        : FilterStream
    {
        private readonly int limit;
        private readonly bool m_leaveOpen;

        internal byte[][] tmpBuffers;

        internal static int FindLimit(Stream input)
        {
            if (input is LimitedInputStream limited)
                return limited.Limit;

            if (input is Asn1InputStream asn1)
                return asn1.limit;

            if (input is MemoryStream memory)
                return Convert.ToInt32(memory.Length - memory.Position);

            return int.MaxValue;
        }

        /**
         * Create an ASN1InputStream based on the input byte array. The length of DER objects in
         * the stream is automatically limited to the length of the input array.
         *
         * @param input array containing ASN.1 encoded data.
         */
        public Asn1InputStream(byte[] input)
            : this(new MemoryStream(input, false), input.Length)
        {
        }

        public Asn1InputStream(Stream input)
            : this(input, FindLimit(input))
        {
        }

        /**
         * Create an ASN1InputStream where no DER object will be longer than limit.
         *
         * @param input stream containing ASN.1 encoded data.
         * @param limit maximum size of a DER encoded object.
         */
        public Asn1InputStream(Stream input, int limit)
            : this(input, limit, false)
        {
        }

        public Asn1InputStream(Stream input, int limit, bool leaveOpen)
            : this(input, limit, leaveOpen, new byte[16][])
        {
        }

        internal Asn1InputStream(Stream input, int limit, bool leaveOpen, byte[][] tmpBuffers)
            : base(input)
        {
            if (!input.CanRead)
                throw new ArgumentException("Expected stream to be readable", nameof(input));

            this.limit = limit;
            m_leaveOpen = leaveOpen;
            this.tmpBuffers = tmpBuffers;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                tmpBuffers = null;
            }

            if (m_leaveOpen)
            {
                base.Detach(disposing);
            }
            else
            {
                base.Dispose(disposing);
            }
        }

        /**
        * build an object given its tag and the number of bytes to construct it from.
        */
        private Asn1Object BuildObject(int tagHdr, int tagNo, int length)
        {
            // TODO[asn1] Special-case zero length first?

            DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(s, length, limit);

            if (0 == (tagHdr & Asn1Tags.Flags))
                return CreatePrimitiveDerObject(tagNo, defIn, tmpBuffers);

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

            using (var sub = new Asn1InputStream(defIn, remaining, leaveOpen: true, tmpBuffers))
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
            int length = ReadLength(s, limit, false);

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
            }

            // indefinite-length

            if (0 == (tagHdr & Asn1Tags.Constructed))
                throw new IOException("indefinite-length primitive encoding encountered");

            IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(s, limit);
            Asn1StreamParser sp = new Asn1StreamParser(indIn, limit, tmpBuffers);

            int tagClass = tagHdr & Asn1Tags.Private;
            if (0 != tagClass)
                return sp.LoadTaggedIL(tagClass, tagNo);

            switch (tagNo)
            {
            case Asn1Tags.BitString:
                return BerBitStringParser.Parse(sp);
            case Asn1Tags.OctetString:
                return BerOctetStringParser.Parse(sp);
            case Asn1Tags.Sequence:
                return BerSequenceParser.Parse(sp);
            case Asn1Tags.Set:
                return BerSetParser.Parse(sp);
            case Asn1Tags.External:
                // TODO[asn1] BerExternalParser
                return DerExternalParser.Parse(sp);
            default:
                throw new IOException("unknown BER object encountered");
            }
        }

        private DerBitString BuildConstructedBitString(Asn1EncodableVector contentsElements)
        {
            DerBitString[] bitStrings = new DerBitString[contentsElements.Count];

            for (int i = 0; i != bitStrings.Length; i++)
            {
                DerBitString bitString = contentsElements[i] as DerBitString;
                if (null == bitString)
                    throw new Asn1Exception("unknown object encountered in constructed BIT STRING: "
                        + Platform.GetTypeName(contentsElements[i]));

                bitStrings[i] = bitString;
            }

            return new DLBitString(BerBitString.FlattenBitStrings(bitStrings), false);
        }

        private Asn1OctetString BuildConstructedOctetString(Asn1EncodableVector contentsElements)
        {
            Asn1OctetString[] octetStrings = new Asn1OctetString[contentsElements.Count];

            for (int i = 0; i != octetStrings.Length; i++)
            {
                Asn1OctetString octetString = contentsElements[i] as Asn1OctetString;
                if (null == octetString)
                    throw new Asn1Exception("unknown object encountered in constructed OCTET STRING: "
                        + Platform.GetTypeName(contentsElements[i]));

                octetStrings[i] = octetString;
            }

            // Note: No DLOctetString available
            return new DerOctetString(BerOctetString.FlattenOctetStrings(octetStrings));
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

        internal static int ReadLength(Stream s, int limit, bool isParsing)
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

            if (length >= limit && !isParsing)   // after all we must have read at least 1 byte
                throw new IOException("corrupted stream - out of bounds length found: " + length + " >= " + limit);

            return length;
        }

        private static bool GetBuffer(DefiniteLengthInputStream defIn, byte[][] tmpBuffers, out byte[] contents)
        {
            int len = defIn.Remaining;
            if (len >= tmpBuffers.Length)
            {
                contents = defIn.ToArray();
                return false;
            }

            byte[] buf = tmpBuffers[len];
            if (buf == null)
            {
                buf = tmpBuffers[len] = new byte[len];
            }

            defIn.ReadAllIntoByteArray(buf);

            contents = buf;
            return true;
        }

        internal static Asn1Object CreatePrimitiveDerObject(int tagNo, DefiniteLengthInputStream defIn,
            byte[][] tmpBuffers)
        {
            switch (tagNo)
            {
            case Asn1Tags.BmpString:
                return CreateDerBmpString(defIn);
            case Asn1Tags.Boolean:
            {
                GetBuffer(defIn, tmpBuffers, out var contents);
                return DerBoolean.CreatePrimitive(contents);
            }
            case Asn1Tags.Enumerated:
            {
                bool usedBuffer = GetBuffer(defIn, tmpBuffers, out var contents);
                return DerEnumerated.CreatePrimitive(contents, clone: usedBuffer);
            }
            case Asn1Tags.ObjectIdentifier:
            {
                bool usedBuffer = GetBuffer(defIn, tmpBuffers, out var contents);
                return DerObjectIdentifier.CreatePrimitive(contents, clone: usedBuffer);
            }
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
            case Asn1Tags.Null:
                return Asn1Null.CreatePrimitive(bytes);
            case Asn1Tags.NumericString:
                return DerNumericString.CreatePrimitive(bytes);
            case Asn1Tags.ObjectDescriptor:
                return Asn1ObjectDescriptor.CreatePrimitive(bytes);
            case Asn1Tags.OctetString:
                return Asn1OctetString.CreatePrimitive(bytes);
            case Asn1Tags.PrintableString:
                return DerPrintableString.CreatePrimitive(bytes);
            case Asn1Tags.RelativeOid:
                return Asn1RelativeOid.CreatePrimitive(bytes, false);
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
            case Asn1Tags.Time:
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

        private static DerBmpString CreateDerBmpString(DefiniteLengthInputStream defIn)
        {
            int remainingBytes = defIn.Remaining;
            if (0 != (remainingBytes & 1))
                throw new IOException("malformed BMPString encoding encountered");

            int length = remainingBytes / 2;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DerBmpString.CreatePrimitive(length, defIn, (str, defIn) =>
            {
                int stringPos = 0;

                Span<byte> buf = stackalloc byte[8];
                while (remainingBytes >= 8)
                {
                    if (Streams.ReadFully(defIn, buf) != 8)
                        throw new EndOfStreamException("EOF encountered in middle of BMPString");

                    str[stringPos    ] = (char)BinaryPrimitives.ReadUInt16BigEndian(buf[0..]);
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
            });
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

            return DerBmpString.CreatePrimitive(str);
#endif
        }
    }
}
