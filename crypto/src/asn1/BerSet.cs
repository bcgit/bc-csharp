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

        internal override void Encode(Asn1OutputStream asn1Out)
        {
            if (asn1Out.IsBer)
            {
                asn1Out.WriteByte(Asn1Tags.Set | Asn1Tags.Constructed);
                asn1Out.WriteByte(0x80);

                foreach (Asn1Encodable o in this)
				{
                    o.ToAsn1Object().Encode(asn1Out);
                }

                asn1Out.WriteByte(0x00);
                asn1Out.WriteByte(0x00);
            }
            else
            {
                base.Encode(asn1Out);
            }
        }
    }
}
