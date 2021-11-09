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

        internal override int EncodedLength(bool withID)
        {
            throw Platform.CreateNotImplementedException("BerSet.EncodedLength");
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (!asn1Out.IsBer)
            {
                base.Encode(asn1Out, withID);
                return;
            }

            asn1Out.WriteEncodingIL(withID, Asn1Tags.Constructed | Asn1Tags.Set, elements);
        }
    }
}
