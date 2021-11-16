using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class BerSet
        : DerSet
    {
		public static new readonly BerSet Empty = new BerSet();

		public static new BerSet FromVector(Asn1EncodableVector elementVector)
		{
            return elementVector.Count < 1 ? Empty : new BerSet(elementVector);
		}

		/**
         * create an empty set
         */
        public BerSet()
            : base()
        {
        }

        /**
         * create a set containing one object
         */
        public BerSet(Asn1Encodable element)
            : base(element)
        {
        }

        public BerSet(params Asn1Encodable[] elements)
            : base(elements, false)
        {
        }

        /**
         * create a set containing a vector of objects.
         */
        public BerSet(Asn1EncodableVector elementVector)
            : base(elementVector, false)
        {
        }

        internal BerSet(bool isSorted, Asn1Encodable[] elements)
            : base(isSorted, elements)
        {
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.EncodedLength(encoding, withID);

            int totalLength = withID ? 4 : 3;

            for (int i = 0, count = elements.Length; i < count; ++i)
            {
                Asn1Object asn1Object = elements[i].ToAsn1Object();
                totalLength += asn1Object.EncodedLength(encoding, true);
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

            asn1Out.WriteEncodingIL(withID, Asn1Tags.Constructed | Asn1Tags.Set, elements);
        }
    }
}
