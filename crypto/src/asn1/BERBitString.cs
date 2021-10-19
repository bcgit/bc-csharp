using System;
using System.Diagnostics;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class BerBitString
        : DerBitString
    {
        private const int DefaultSegmentLimit = 1000;

        internal static byte[] FlattenBitStrings(DerBitString[] bitStrings)
        {
            int count = bitStrings.Length;
            switch (count)
            {
            case 0:
                // No bits
                return new byte[]{ 0 };
            case 1:
                return bitStrings[0].contents;
            default:
            {
                int last = count - 1, totalLength = 0;
                for (int i = 0; i < last; ++i)
                {
                    byte[] elementContents = bitStrings[i].contents;
                    if (elementContents[0] != 0)
                        throw new ArgumentException("only the last nested bitstring can have padding", "bitStrings");

                    totalLength += elementContents.Length - 1;
                }

                // Last one can have padding
                byte[] lastElementContents = bitStrings[last].contents;
                byte padBits = lastElementContents[0];
                totalLength += lastElementContents.Length;

                byte[] contents = new byte[totalLength];
                contents[0] = padBits;

                int pos = 1;
                for (int i = 0; i < count; ++i)
                {
                    byte[] elementContents = bitStrings[i].contents;
                    int length = elementContents.Length - 1;
                    Array.Copy(elementContents, 1, contents, pos, length);
                    pos += length;
                }

                Debug.Assert(pos == totalLength);
                return contents;
            }
            }
        }

        private readonly int segmentLimit;
        private readonly DerBitString[] elements;

        public BerBitString(byte data, int padBits)
            : base(data, padBits)
        {
            this.elements = null;
            this.segmentLimit = DefaultSegmentLimit;
        }

        public BerBitString(byte[] data)
            : this(data, 0)
        {
        }

        public BerBitString(byte[] data, int padBits)
            : this(data, padBits, DefaultSegmentLimit)
		{
        }

        public BerBitString(byte[] data, int padBits, int segmentLimit)
            : base(data, padBits)
        {
            this.elements = null;
            this.segmentLimit = segmentLimit;
        }

        public BerBitString(int namedBits)
            : base(namedBits)
        {
            this.elements = null;
            this.segmentLimit = DefaultSegmentLimit;
        }

        public BerBitString(Asn1Encodable obj)
            : this(obj.GetDerEncoded(), 0)
		{
        }

        public BerBitString(DerBitString[] elements)
            : this(elements, DefaultSegmentLimit)
        {
        }

        public BerBitString(DerBitString[] elements, int segmentLimit)
            : base(FlattenBitStrings(elements), false)
        {
            this.elements = elements;
            this.segmentLimit = segmentLimit;
        }

        internal BerBitString(byte[] contents, bool check)
            : base(contents, check)
        {
            this.elements = null;
            this.segmentLimit = DefaultSegmentLimit;
        }

        private bool IsConstructed
        {
            get { return null != elements || contents.Length > segmentLimit; }
        }

        internal override int EncodedLength(bool withID)
        {
            throw Platform.CreateNotImplementedException("BerBitString.EncodedLength");

            // TODO This depends on knowing it's not DER
            //if (!IsConstructed)
            //    return EncodedLength(withID, contents.Length);

            //int totalLength = withID ? 4 : 3;

            //if (null != elements)
            //{
            //    for (int i = 0; i < elements.Length; ++i)
            //    {
            //        totalLength += elements[i].EncodedLength(true);
            //    }
            //}
            //else if (contents.Length < 2)
            //{
            //    // No bits
            //}
            //else
            //{
            //    int extraSegments = (contents.Length - 2) / (segmentLimit - 1);
            //    totalLength += extraSegments * EncodedLength(true, segmentLimit);

            //    int lastSegmentLength = contents.Length - (extraSegments * (segmentLimit - 1));
            //    totalLength += EncodedLength(true, lastSegmentLength);
            //}

            //return totalLength;
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (!asn1Out.IsBer)
            {
                base.Encode(asn1Out, withID);
                return;
            }

            if (!IsConstructed)
            {
                Encode(asn1Out, withID, contents, 0, contents.Length);
                return;
            }

            asn1Out.WriteIdentifier(withID, Asn1Tags.Constructed | Asn1Tags.BitString);
            asn1Out.WriteByte(0x80);

            if (null != elements)
            {
                asn1Out.WritePrimitives(elements);
            }
            else if (contents.Length < 2)
            {
                // No bits
            }
            else
            {
                byte pad = contents[0];
                int length = contents.Length;
                int remaining = length - 1;
                int segmentLength = segmentLimit - 1;

                while (remaining > segmentLength)
                {
                    Encode(asn1Out, true, (byte)0, contents, length - remaining, segmentLength);
                    remaining -= segmentLength;
                }

                Encode(asn1Out, true, pad, contents, length - remaining, remaining);
            }

            asn1Out.WriteByte(0x00);
            asn1Out.WriteByte(0x00);
        }
    }
}
