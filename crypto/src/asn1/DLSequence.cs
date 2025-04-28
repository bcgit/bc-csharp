using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    public class DLSequence
        : DerSequence
    {
        public static new readonly DLSequence Empty = new DLSequence();

        public static new DLSequence Concatenate(params Asn1Sequence[] sequences)
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

        public static new DLSequence FromCollection(IReadOnlyCollection<Asn1Encodable> elements)
        {
            return elements.Count < 1 ? Empty : new DLSequence(elements);
        }

        public static new DLSequence FromElement(Asn1Encodable element) => new DLSequence(element);

        public static new DLSequence FromElements(Asn1Encodable element1, Asn1Encodable element2) =>
            new DLSequence(element1, element2);

        public static new DLSequence FromElements(Asn1Encodable[] elements)
        {
            if (elements == null)
                throw new ArgumentNullException(nameof(elements));

            return elements.Length < 1 ? Empty : new DLSequence(elements);
        }

        public static new DLSequence FromElementsOptional(Asn1Encodable[] elements)
        {
            if (elements == null)
                return null;

            return elements.Length < 1 ? Empty : new DLSequence(elements);
        }

        public static new DLSequence FromSequence(Asn1Sequence sequence)
        {
            if (sequence is DLSequence dlSequence)
                return dlSequence;

            return WithElements(sequence.m_elements);
        }

        public static new DLSequence FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DLSequence(elementVector);
        }

        public static new DLSequence Map(Asn1Sequence sequence, Func<Asn1Encodable, Asn1Encodable> func)
        {
            return sequence.Count < 1 ? Empty : new DLSequence(sequence.MapElements(func), clone: false);
        }

        public static new DLSequence Map<T>(T[] ts, Func<T, Asn1Encodable> func)
        {
            return ts.Length < 1 ? Empty : new DLSequence(CollectionUtilities.Map(ts, func), clone: false);
        }

        public static new DLSequence Map<T>(IReadOnlyCollection<T> c, Func<T, Asn1Encodable> func)
        {
            return c.Count < 1 ? Empty : new DLSequence(CollectionUtilities.Map(c, func), clone: false);
        }

        internal static new DLSequence WithElements(Asn1Encodable[] elements)
        {
            return elements.Length < 1 ? Empty : new DLSequence(elements, clone: false);
        }

        public DLSequence()
            : base()
        {
        }

        public DLSequence(Asn1Encodable element)
            : base(element)
        {
        }

        public DLSequence(Asn1Encodable element1, Asn1Encodable element2)
            : base(element1, element2)
        {
        }

        public DLSequence(params Asn1Encodable[] elements)
            : base(elements)
        {
        }

        public DLSequence(Asn1EncodableVector elementVector)
            : base(elementVector)
        {
        }

        public DLSequence(IReadOnlyCollection<Asn1Encodable> elements)
            : base(elements)
        {
        }

        internal DLSequence(Asn1Encodable[] elements, bool clone)
            : base(elements, clone)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncoding(encoding);

            return new ConstructedDLEncoding(Asn1Tags.Universal, Asn1Tags.Sequence,
                Asn1OutputStream.GetContentsEncodings(Asn1OutputStream.EncodingDL, m_elements));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            return new ConstructedDLEncoding(tagClass, tagNo,
                Asn1OutputStream.GetContentsEncodings(Asn1OutputStream.EncodingDL, m_elements));
        }

        internal override DerBitString ToAsn1BitString() =>
            new DLBitString(BerBitString.FlattenBitStrings(GetConstructedBitStrings()), false);

        internal override DerExternal ToAsn1External() => new DLExternal(this);

        internal override Asn1Set ToAsn1Set() => new DLSet(false, m_elements);
    }
}
