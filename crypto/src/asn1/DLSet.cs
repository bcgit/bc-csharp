using System;

namespace Org.BouncyCastle.Asn1
{
    public class DLSet
        : DerSet
    {
        public static new readonly DLSet Empty = new DLSet();

        public static new DLSet FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DLSet(elementVector);
        }

        /**
         * create an empty set
         */
        public DLSet()
            : base()
        {
        }

        /**
         * create a set containing one object
         */
        public DLSet(Asn1Encodable element)
            : base(element)
        {
        }

        public DLSet(params Asn1Encodable[] elements)
            : base(elements, false)
        {
        }

        /**
         * create a set containing a vector of objects.
         */
        public DLSet(Asn1EncodableVector elementVector)
            : base(elementVector, false)
        {
        }

        internal DLSet(bool isSorted, Asn1Encodable[] elements)
            : base(isSorted, elements)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncoding(encoding);

            return new ConstructedDLEncoding(Asn1Tags.Universal, Asn1Tags.Set,
                Asn1OutputStream.GetContentsEncodings(Asn1OutputStream.EncodingDL, m_elements));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            return new ConstructedDLEncoding(tagClass, tagNo,
                Asn1OutputStream.GetContentsEncodings(Asn1OutputStream.EncodingDL, m_elements));
        }
    }
}
