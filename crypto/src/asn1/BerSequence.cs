using System;

namespace Org.BouncyCastle.Asn1
{
	public class BerSequence
		: DLSequence
	{
		public static new readonly BerSequence Empty = new BerSequence();

        public static new BerSequence Concatenate(params Asn1Sequence[] sequences)
        {
            if (sequences == null)
                return Empty;

            switch (sequences.Length)
            {
            case 0:
                return Empty;
            case 1:
                return FromSequence(sequences[0]);
            default:
                return WithElements(ConcatenateElements(sequences));
            }
        }

        public static new BerSequence FromElements(Asn1Encodable[] elements)
        {
            if (elements == null)
                throw new ArgumentNullException(nameof(elements));

            return elements.Length < 1 ? Empty : new BerSequence(elements);
        }

        public static new BerSequence FromElementsOptional(Asn1Encodable[] elements)
        {
            if (elements == null)
                return null;

            return elements.Length < 1 ? Empty : new BerSequence(elements);
        }

        public static new BerSequence FromSequence(Asn1Sequence sequence)
        {
            if (sequence is BerSequence berSequence)
                return berSequence;

            return WithElements(sequence.m_elements);
        }

		public static new BerSequence FromVector(Asn1EncodableVector elementVector)
		{
            return elementVector.Count < 1 ? Empty : new BerSequence(elementVector);
		}

        public static new BerSequence Map(Asn1Sequence sequence, Func<Asn1Encodable, Asn1Encodable> func)
        {
            return sequence.Count < 1 ? Empty : new BerSequence(sequence.MapElements(func), clone: false);
        }

        internal static new BerSequence WithElements(Asn1Encodable[] elements)
        {
            return elements.Length < 1 ? Empty : new BerSequence(elements, clone: false);
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

        /**
		 * create a sequence containing two objects
		 */
        public BerSequence(Asn1Encodable element1, Asn1Encodable element2)
            : base(element1, element2)
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

        internal BerSequence(Asn1Encodable[] elements, bool clone)
            : base(elements, clone)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.GetEncoding(encoding);

            return new ConstructedILEncoding(Asn1Tags.Universal, Asn1Tags.Sequence,
                Asn1OutputStream.GetContentsEncodings(encoding, m_elements));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            return new ConstructedILEncoding(tagClass, tagNo,
                Asn1OutputStream.GetContentsEncodings(encoding, m_elements));
        }

        internal override DerBitString ToAsn1BitString()
        {
            return new BerBitString(GetConstructedBitStrings());
        }

        internal override DerExternal ToAsn1External()
        {
            // TODO[asn1] There is currently no BerExternal (or Asn1External)
            return new DLExternal(this);
        }

        internal override Asn1OctetString ToAsn1OctetString()
        {
            return new BerOctetString(GetConstructedOctetStrings());
        }

        internal override Asn1Set ToAsn1Set()
        {
            return new BerSet(false, m_elements);
        }
    }
}
