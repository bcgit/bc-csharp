using System;

namespace Org.BouncyCastle.Asn1
{
	public class DerSequence
		: Asn1Sequence
	{
		public static readonly DerSequence Empty = new DerSequence();

		public static DerSequence FromVector(Asn1EncodableVector elementVector)
		{
            return elementVector.Count < 1 ? Empty : new DerSequence(elementVector);
		}

        private int m_contentsLengthDer = -1;

        /**
		 * create an empty sequence
		 */
        public DerSequence()
			: base()
		{
		}

		/**
		 * create a sequence containing one object
		 */
		public DerSequence(Asn1Encodable element)
			: base(element)
		{
		}

		public DerSequence(params Asn1Encodable[] elements)
            : base(elements)
		{
		}

		/**
		 * create a sequence containing a vector of objects.
		 */
		public DerSequence(Asn1EncodableVector elementVector)
            : base(elementVector)
		{
		}

        internal DerSequence(Asn1Encodable[] elements, bool clone)
            : base(elements, clone)
        {
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(withID, GetContentsLengthDer());
        }

        /*
		 * A note on the implementation:
		 * <p>
		 * As Der requires the constructed, definite-length model to
		 * be used for structured types, this varies slightly from the
		 * ASN.1 descriptions given. Rather than just outputing Sequence,
		 * we also have to specify Constructed, and the objects length.
		 */
        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            asn1Out = asn1Out.GetDerSubStream();

            asn1Out.WriteIdentifier(withID, Asn1Tags.Constructed | Asn1Tags.Sequence);

            int count = elements.Length;
            if (m_contentsLengthDer >= 0 || count > 16)
            {
                asn1Out.WriteDL(GetContentsLengthDer());

                for (int i = 0; i < count; ++i)
                {
                    Asn1Object asn1Object = elements[i].ToAsn1Object();
                    asn1Object.Encode(asn1Out, true);
                }
            }
            else
            {
                int contentsLength = 0;

                Asn1Object[] asn1Objects = new Asn1Object[count];
                for (int i = 0; i < count; ++i)
                {
                    Asn1Object asn1Object = elements[i].ToAsn1Object();
                    asn1Objects[i] = asn1Object;
                    contentsLength += asn1Object.EncodedLength(asn1Out.Encoding, true);
                }

                this.m_contentsLengthDer = contentsLength;
                asn1Out.WriteDL(contentsLength);

                for (int i = 0; i < count; ++i)
                {
                    asn1Objects[i].Encode(asn1Out, true);
                }
            }
        }

        internal override DerBitString ToAsn1BitString()
        {
            return new DerBitString(BerBitString.FlattenBitStrings(GetConstructedBitStrings()), false);
        }

        internal override DerExternal ToAsn1External()
        {
            return new DerExternal(this);
        }

        internal override Asn1OctetString ToAsn1OctetString()
        {
            return new DerOctetString(BerOctetString.FlattenOctetStrings(GetConstructedOctetStrings()));
        }

        internal override Asn1Set ToAsn1Set()
        {
            // NOTE: DLSet is intentional, we don't want sorting
            return new DLSet(false, elements);
        }

        private int GetContentsLengthDer()
        {
            if (m_contentsLengthDer < 0)
            {
                m_contentsLengthDer = CalculateContentsLength(Asn1OutputStream.EncodingDer);
            }
            return m_contentsLengthDer;
        }
    }
}
