using System;
using System.Collections;
using System.Diagnostics;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class BerOctetString
        : DerOctetString, IEnumerable
    {
        private const int DefaultSegmentLimit = 1000;

        public static BerOctetString FromSequence(Asn1Sequence seq)
        {
            int count = seq.Count;
            Asn1OctetString[] v = new Asn1OctetString[count];
            for (int i = 0; i < count; ++i)
            {
                v[i] = GetInstance(seq[i]);
            }
            return new BerOctetString(v);
        }

        internal static byte[] FlattenOctetStrings(Asn1OctetString[] octetStrings)
        {
            int count = octetStrings.Length;
            switch (count)
            {
            case 0:
                return EmptyOctets;
            case 1:
                return octetStrings[0].contents;
            default:
            {
                int totalOctets = 0;
                for (int i = 0; i < count; ++i)
                {
                    totalOctets += octetStrings[i].contents.Length;
                }

                byte[] str = new byte[totalOctets];
                int pos = 0;
                for (int i = 0; i < count; ++i)
                {
                    byte[] octets = octetStrings[i].contents;
                    Array.Copy(octets, 0, str, pos, octets.Length);
                    pos += octets.Length;
                }

                Debug.Assert(pos == totalOctets);
                return str;
            }
            }
        }

        private static Asn1OctetString[] ToOctetStringArray(IEnumerable e)
        {
            IList list = Platform.CreateArrayList(e);

            int count = list.Count;
            Asn1OctetString[] v = new Asn1OctetString[count];
            for (int i = 0; i < count; ++i)
            {
                v[i] = GetInstance(list[i]);
            }
            return v;
        }

        private readonly int segmentLimit;
        private readonly Asn1OctetString[] elements;

        [Obsolete("Will be removed")]
        public BerOctetString(IEnumerable e)
            : this(ToOctetStringArray(e))
        {
        }

        public BerOctetString(byte[] contents)
			: this(contents, DefaultSegmentLimit)
		{
		}

        public BerOctetString(Asn1OctetString[] elements)
            : this(elements, DefaultSegmentLimit)
        {
        }

        public BerOctetString(byte[] contents, int segmentLimit)
            : this(contents, null, segmentLimit)
        {
        }

        public BerOctetString(Asn1OctetString[] elements, int segmentLimit)
            : this(FlattenOctetStrings(elements), elements, segmentLimit)
        {
        }

        private BerOctetString(byte[] contents, Asn1OctetString[] elements, int segmentLimit)
            : base(contents)
        {
            this.elements = elements;
            this.segmentLimit = segmentLimit;
        }

        /**
         * return the DER octets that make up this string.
         */
		public IEnumerator GetEnumerator()
		{
			if (elements == null)
                return new ChunkEnumerator(contents, segmentLimit);

			return elements.GetEnumerator();
		}

		[Obsolete("Use GetEnumerator() instead")]
        public IEnumerator GetObjects()
        {
			return GetEnumerator();
		}

        internal override bool EncodeConstructed(int encoding)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.EncodeConstructed(encoding);

            return null != elements || contents.Length > segmentLimit;
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.EncodedLength(encoding, withID);

            if (!EncodeConstructed(encoding))
                return EncodedLength(withID, contents.Length);

            int totalLength = withID ? 4 : 3;

            if (null != elements)
            {
                for (int i = 0; i < elements.Length; ++i)
                {
                    totalLength += elements[i].EncodedLength(encoding, true);
                }
            }
            else
            {
                int fullSegments = contents.Length / segmentLimit;
                totalLength += fullSegments * EncodedLength(true, segmentLimit);

                int lastSegmentLength = contents.Length - (fullSegments * segmentLimit);
                if (lastSegmentLength > 0)
                {
                    totalLength += EncodedLength(true, lastSegmentLength);
                }
            }

            return totalLength;
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (Asn1OutputStream.EncodingBer != asn1Out.Encoding)
            {
                base.Encode(asn1Out, withID);
                return;
            }

            if (!EncodeConstructed(asn1Out.Encoding))
            {
                Encode(asn1Out, withID, contents, 0, contents.Length);
                return;
            }

            asn1Out.WriteIdentifier(withID, Asn1Tags.Constructed | Asn1Tags.OctetString);
            asn1Out.WriteByte(0x80);

            if (null != elements)
            {
                asn1Out.WritePrimitives(elements);
            }
            else
            {
                int pos = 0;
                while (pos < contents.Length)
                {
                    int segmentLength = System.Math.Min(contents.Length - pos, segmentLimit);
                    Encode(asn1Out, true, contents, pos, segmentLength);
                    pos += segmentLength;
                }
            }

            asn1Out.WriteByte(0x00);
            asn1Out.WriteByte(0x00);
        }

        private class ChunkEnumerator
            : IEnumerator
        {
            private readonly byte[] octets;
            private readonly int segmentLimit;

            private DerOctetString currentSegment = null;
            private int nextSegmentPos = 0;

            internal ChunkEnumerator(byte[] octets, int segmentLimit)
            {
                this.octets = octets;
                this.segmentLimit = segmentLimit;
            }

            public object Current
            {
                get
                {
                    if (null == currentSegment)
                        throw new InvalidOperationException();

                    return currentSegment;
                }
            }

            public bool MoveNext()
            {
                if (nextSegmentPos >= octets.Length)
                {
                    this.currentSegment = null;
                    return false;
                }

                int length = System.Math.Min(octets.Length - nextSegmentPos, segmentLimit);
                byte[] segment = new byte[length];
                Array.Copy(octets, nextSegmentPos, segment, 0, length);
                this.currentSegment = new DerOctetString(segment);
                this.nextSegmentPos += length;
                return true;
            }

            public void Reset()
            {
                this.currentSegment = null;
                this.nextSegmentPos = 0;
            }
        }
    }
}
