using System;

namespace Org.BouncyCastle.Asn1
{
	/**
	 * A Der encoded set object
	 */
	public class DerSet
		: Asn1Set
	{
		public static readonly DerSet Empty = new DerSet();

		public static DerSet FromVector(Asn1EncodableVector elementVector)
		{
            return elementVector.Count < 1 ? Empty : new DerSet(elementVector);
		}

        private int m_contentsLengthDer = -1;

        /**
		 * create an empty set
		 */
        public DerSet()
			: base()
		{
		}

		/**
		 * @param obj - a single object that makes up the set.
		 */
		public DerSet(Asn1Encodable element)
			: base(element)
		{
		}

        public DerSet(params Asn1Encodable[] elements)
            : base(elements, true)
        {
        }

        internal DerSet(Asn1Encodable[] elements, bool doSort)
			: base(elements, doSort)
		{
		}

		/**
		 * @param v - a vector of objects making up the set.
		 */
		public DerSet(Asn1EncodableVector elementVector)
			: base(elementVector, true)
		{
		}

		internal DerSet(Asn1EncodableVector	elementVector, bool doSort)
			: base(elementVector, doSort)
		{
		}

        internal DerSet(bool isSorted, Asn1Encodable[] elements)
            : base(isSorted, elements)
        {
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            encoding = Asn1OutputStream.EncodingDer;

            int count = elements.Length;
            int contentsLength = 0;

            for (int i = 0; i < count; ++i)
            {
                Asn1Object asn1Object = elements[i].ToAsn1Object();
                contentsLength += asn1Object.EncodedLength(encoding, true);
            }

            return Asn1OutputStream.GetLengthOfEncodingDL(withID, contentsLength);
        }

        /*
		 * A note on the implementation:
		 * <p>
		 * As Der requires the constructed, definite-length model to
		 * be used for structured types, this varies slightly from the
		 * ASN.1 descriptions given. Rather than just outputing Set,
		 * we also have to specify Constructed, and the objects length.
		 */
        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (Count < 1)
            {
                asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.Set, Asn1OctetString.EmptyOctets);
                return;
            }

            Asn1Encodable[] elements = this.elements;
            if (!isSorted)
            {
                elements = Sort((Asn1Encodable[])elements.Clone());
            }

            asn1Out = asn1Out.GetDerSubStream();

            asn1Out.WriteIdentifier(withID, Asn1Tags.Constructed | Asn1Tags.Set);

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
