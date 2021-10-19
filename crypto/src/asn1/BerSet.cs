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

        internal static new BerSet FromVector(Asn1EncodableVector elementVector, bool needsSorting)
		{
            return elementVector.Count < 1 ? Empty : new BerSet(elementVector, needsSorting);
		}

		/**
         * create an empty sequence
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

        /**
         * create a set containing a vector of objects.
         */
        public BerSet(Asn1EncodableVector elementVector)
            : base(elementVector, false)
        {
        }

        internal BerSet(Asn1EncodableVector elementVector, bool needsSorting)
            : base(elementVector, needsSorting)
        {
        }

        internal override int EncodedLength(bool withID)
        {
            throw Platform.CreateNotImplementedException("BerSet.EncodedLength");
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (asn1Out.IsBer)
            {
                asn1Out.WriteEncodingIL(withID, Asn1Tags.Constructed | Asn1Tags.Set, elements);
            }
            else
            {
                base.Encode(asn1Out, withID);
            }
        }
    }
}
