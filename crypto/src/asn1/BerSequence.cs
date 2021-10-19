using System;

using Org.BouncyCastle.Utilities;

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

        internal override int EncodedLength(bool withID)
        {
            throw Platform.CreateNotImplementedException("BerSequence.EncodedLength");
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
		{
			if (asn1Out.IsBer)
            {
                asn1Out.WriteEncodingIL(withID, Asn1Tags.Constructed | Asn1Tags.Sequence, elements);
			}
			else
			{
				base.Encode(asn1Out, withID);
			}
		}
	}
}
