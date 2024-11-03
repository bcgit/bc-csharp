using System;

namespace Org.BouncyCastle.Asn1
{
	public class DerSequence
		: Asn1Sequence
	{
		public static readonly DerSequence Empty = new DerSequence();

        public static DerSequence Concatenate(params Asn1Sequence[] sequences)
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

        public static DerSequence FromElements(Asn1Encodable[] elements)
        {
            if (elements == null)
                throw new ArgumentNullException(nameof(elements));

            return elements.Length < 1 ? Empty : new DerSequence(elements);
        }

        public static DerSequence FromElementsOptional(Asn1Encodable[] elements)
        {
            if (elements == null)
                return null;

            return elements.Length < 1 ? Empty : new DerSequence(elements);
        }

        public static DerSequence FromSequence(Asn1Sequence sequence)
        {
            if (sequence is DerSequence derSequence)
                return derSequence;

            return WithElements(sequence.m_elements);
        }

		public static DerSequence FromVector(Asn1EncodableVector elementVector)
		{
            return elementVector.Count < 1 ? Empty : new DerSequence(elementVector);
		}

        public static DerSequence Map(Asn1Sequence sequence, Func<Asn1Encodable, Asn1Encodable> func)
        {
            return sequence.Count < 1 ? Empty : new DerSequence(sequence.MapElements(func), clone: false);
        }

        internal static DerSequence WithElements(Asn1Encodable[] elements)
        {
            return elements.Length < 1 ? Empty : new DerSequence(elements, clone: false);
        }

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

        /**
		 * create a sequence containing two objects
		 */
        public DerSequence(Asn1Encodable element1, Asn1Encodable element2)
            : base(element1, element2)
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

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new ConstructedDLEncoding(Asn1Tags.Universal, Asn1Tags.Sequence,
                Asn1OutputStream.GetContentsEncodings(Asn1OutputStream.EncodingDer, m_elements));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new ConstructedDLEncoding(tagClass, tagNo,
                Asn1OutputStream.GetContentsEncodings(Asn1OutputStream.EncodingDer, m_elements));
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new ConstructedDerEncoding(Asn1Tags.Universal, Asn1Tags.Sequence,
                Asn1OutputStream.GetContentsEncodingsDer(m_elements));
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new ConstructedDerEncoding(tagClass, tagNo,
                Asn1OutputStream.GetContentsEncodingsDer(m_elements));
        }

        internal override DerBitString ToAsn1BitString()
        {
            return new DerBitString(BerBitString.FlattenBitStrings(GetConstructedBitStrings()), false);
        }

        internal override DerExternal ToAsn1External()
        {
            return new DerExternal(this);
        }

        internal override Asn1OctetString ToAsn1OctetString() =>
            DerOctetString.WithContents(BerOctetString.FlattenOctetStrings(GetConstructedOctetStrings()));

        internal override Asn1Set ToAsn1Set()
        {
            // NOTE: DLSet is intentional, we don't want sorting
            return new DLSet(false, m_elements);
        }

        internal static int GetEncodingLength(int contentsLength)
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(Asn1Tags.Sequence, contentsLength);
        }
    }
}
