namespace Org.BouncyCastle.Asn1
{
	public class BerSequence
		: DerSequence
	{
		public static new readonly BerSequence Empty = new BerSequence();

		public static new BerSequence FromVector(Asn1EncodableVector elementVector)
		{
            return elementVector.Count < 1 ? Empty : new BerSequence(elementVector);
		}

		/**
		 * create an empty sequence
		 */
		public BerSequence()
            : base()
		{
		}

		/**
		 * create a sequence containing one object
		 */
		public BerSequence(Asn1Encodable element)
            : base(element)
		{
		}

		public BerSequence(params Asn1Encodable[] elements)
            : base(elements)
		{
		}

		/**
		 * create a sequence containing a vector of objects.
		 */
		public BerSequence(Asn1EncodableVector elementVector)
            : base(elementVector)
		{
		}

        internal override void Encode(Asn1OutputStream asn1Out)
		{
			if (asn1Out.IsBer)
			{
				asn1Out.WriteByte(Asn1Tags.Sequence | Asn1Tags.Constructed);
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
