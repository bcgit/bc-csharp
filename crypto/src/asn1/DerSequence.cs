using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 SEQUENCE with DER encoding.</summary>
    public class DerSequence
        : Asn1Sequence
    {
        /// <summary>The empty <see cref="DerSequence"/>.</summary>
        public static readonly DerSequence Empty = new DerSequence();

        /// <summary>
        /// Create a <see cref="DerSequence"/> holding the elements of all the given sequences, in order.
        /// </summary>
        /// <param name="sequences">The sequences to concatenate, or null.</param>
        /// <returns>The concatenated <see cref="DerSequence"/>.</returns>
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

        /// <summary>Create a <see cref="DerSequence"/> from a collection of elements.</summary>
        /// <param name="elements">The elements.</param>
        /// <returns>The new <see cref="DerSequence"/>.</returns>
        public static DerSequence FromCollection(IReadOnlyCollection<Asn1Encodable> elements)
        {
            return elements.Count < 1 ? Empty : new DerSequence(elements);
        }

        /// <summary>Create a <see cref="DerSequence"/> holding a single element.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The new <see cref="DerSequence"/>.</returns>
        public static DerSequence FromElement(Asn1Encodable element) => new DerSequence(element);

        /// <summary>Create a <see cref="DerSequence"/> holding two elements.</summary>
        /// <param name="element1">The first element.</param>
        /// <param name="element2">The second element.</param>
        /// <returns>The new <see cref="DerSequence"/>.</returns>
        public static DerSequence FromElements(Asn1Encodable element1, Asn1Encodable element2) =>
            new DerSequence(element1, element2);

        /// <summary>Create a <see cref="DerSequence"/> from an array of elements.</summary>
        /// <param name="elements">The elements.</param>
        /// <returns>The new <see cref="DerSequence"/>.</returns>
        public static DerSequence FromElements(Asn1Encodable[] elements)
        {
            if (elements == null)
                throw new ArgumentNullException(nameof(elements));

            return elements.Length < 1 ? Empty : new DerSequence(elements);
        }

        /// <summary>
        /// Create a <see cref="DerSequence"/> from an array of elements, or null if the array is null.
        /// </summary>
        /// <param name="elements">The elements, or null.</param>
        /// <returns>The new <see cref="DerSequence"/>, or null if <paramref name="elements"/> is null.</returns>
        public static DerSequence FromElementsOptional(Asn1Encodable[] elements)
        {
            if (elements == null)
                return null;

            return elements.Length < 1 ? Empty : new DerSequence(elements);
        }

        /// <summary>Create a <see cref="DerSequence"/> with the elements of another sequence.</summary>
        /// <param name="sequence">The sequence.</param>
        /// <returns>The new <see cref="DerSequence"/>, or the argument itself if it is already of this type.</returns>
        public static DerSequence FromSequence(Asn1Sequence sequence)
        {
            if (sequence is DerSequence derSequence)
                return derSequence;

            return WithElements(sequence.m_elements);
        }

        /// <summary>Create a <see cref="DerSequence"/> from the elements of a vector.</summary>
        /// <param name="elementVector">The vector of elements.</param>
        /// <returns>The new <see cref="DerSequence"/>.</returns>
        public static DerSequence FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DerSequence(elementVector);
        }

        /// <summary>Create a <see cref="DerSequence"/> by applying a function to each element of the source.</summary>
        /// <param name="sequence">The source sequence.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="DerSequence"/>.</returns>
        public static DerSequence Map(Asn1Sequence sequence, Func<Asn1Encodable, Asn1Encodable> func)
        {
            return sequence.Count < 1 ? Empty : new DerSequence(sequence.MapElements(func), clone: false);
        }

        /// <summary>Create a <see cref="DerSequence"/> by applying a function to each element of the source.</summary>
        /// <param name="ts">The source array.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="DerSequence"/>.</returns>
        public static DerSequence Map<T>(T[] ts, Func<T, Asn1Encodable> func)
        {
            return ts.Length < 1 ? Empty : new DerSequence(CollectionUtilities.Map(ts, func), clone: false);
        }

        /// <summary>Create a <see cref="DerSequence"/> by applying a function to each element of the source.</summary>
        /// <param name="c">The source collection.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="DerSequence"/>.</returns>
        public static DerSequence Map<T>(IReadOnlyCollection<T> c, Func<T, Asn1Encodable> func)
        {
            return c.Count < 1 ? Empty : new DerSequence(CollectionUtilities.Map(c, func), clone: false);
        }

        internal static DerSequence WithElements(Asn1Encodable[] elements)
        {
            return elements.Length < 1 ? Empty : new DerSequence(elements, clone: false);
        }

        /// <summary>Create a new <see cref="DerSequence"/>.</summary>
        public DerSequence()
            : base()
        {
        }

        /// <summary>Create a new <see cref="DerSequence"/>.</summary>
        /// <param name="element">The element.</param>
        public DerSequence(Asn1Encodable element)
            : base(element)
        {
        }

        /// <summary>Create a new <see cref="DerSequence"/>.</summary>
        /// <param name="element1">The element 1.</param>
        /// <param name="element2">The element 2.</param>
        public DerSequence(Asn1Encodable element1, Asn1Encodable element2)
            : base(element1, element2)
        {
        }

        /// <summary>Create a new <see cref="DerSequence"/>.</summary>
        /// <param name="elements">The elements.</param>
        public DerSequence(params Asn1Encodable[] elements)
            : base(elements)
        {
        }

        /// <summary>Create a new <see cref="DerSequence"/>.</summary>
        /// <param name="elementVector">The element vector.</param>
        public DerSequence(Asn1EncodableVector elementVector)
            : base(elementVector)
        {
        }

        /// <summary>Create a new <see cref="DerSequence"/>.</summary>
        /// <param name="elements">The elements.</param>
        public DerSequence(IReadOnlyCollection<Asn1Encodable> elements)
            : base(elements)
        {
        }

        /// <summary>Create a new <see cref="DerSequence"/>.</summary>
        /// <param name="sequence">The sequence.</param>
        public DerSequence(Asn1Sequence sequence)
            : base(element: sequence)
        {
        }

        /// <summary>Create a new <see cref="DerSequence"/>.</summary>
        /// <param name="asn1Set">The asn 1 set.</param>
        public DerSequence(Asn1Set asn1Set)
            : base(element: asn1Set)
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
            return new ConstructedDerEncoding(tagClass, tagNo, Asn1OutputStream.GetContentsEncodingsDer(m_elements));
        }

        internal override DerBitString ToAsn1BitString() =>
            new DerBitString(BerBitString.FlattenBitStrings(GetConstructedBitStrings()), false);

        internal override DerExternal ToAsn1External() => DerExternal.FromSequence(this);

        internal override Asn1OctetString ToAsn1OctetString() =>
            DerOctetString.WithContents(BerOctetString.FlattenOctetStrings(GetConstructedOctetStrings()));

        // NOTE: DLSet is intentional, we don't want sorting
        internal override Asn1Set ToAsn1Set() => new DLSet(false, m_elements);

        internal static int GetEncodingLength(int contentsLength) =>
            Asn1OutputStream.GetLengthOfEncodingDL(Asn1Tags.Sequence, contentsLength);
    }
}
