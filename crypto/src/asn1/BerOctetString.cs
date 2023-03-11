using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Asn1
{
    public class BerOctetString
        : DerOctetString
    {
        public static BerOctetString FromSequence(Asn1Sequence seq)
        {
            return new BerOctetString(seq.MapElements(GetInstance));
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

        private readonly Asn1OctetString[] elements;

        public BerOctetString(byte[] contents)
			: this(contents, null)
		{
		}

        public BerOctetString(Asn1OctetString[] elements)
            : this(FlattenOctetStrings(elements), elements)
        {
        }

        [Obsolete("Use version without segmentLimit (which is ignored anyway)")]
        public BerOctetString(byte[] contents, int segmentLimit)
            : this(contents)
        {
        }

        [Obsolete("Use version without segmentLimit (which is ignored anyway)")]
        public BerOctetString(Asn1OctetString[] elements, int segmentLimit)
            : this(elements)
        {
        }

        private BerOctetString(byte[] contents, Asn1OctetString[] elements)
            : base(contents)
        {
            this.elements = elements;
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.GetEncoding(encoding);

            if (null == elements)
                return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.OctetString, contents);

            return new ConstructedILEncoding(Asn1Tags.Universal, Asn1Tags.OctetString,
                Asn1OutputStream.GetContentsEncodings(encoding, elements));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            if (null == elements)
                return new PrimitiveEncoding(tagClass, tagNo, contents);

            return new ConstructedILEncoding(tagClass, tagNo,
                Asn1OutputStream.GetContentsEncodings(encoding, elements));
        }
    }
}
