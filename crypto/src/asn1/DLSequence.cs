using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 SEQUENCE with definite-length (DL) encoding.</summary>
    public class DLSequence
        : DerSequence
    {
        /// <summary>The empty <see cref="DLSequence"/>.</summary>
        public static new readonly DLSequence Empty = new DLSequence();

        /// <summary>
        /// Create a <see cref="DLSequence"/> holding the elements of all the given sequences, in order.
        /// </summary>
        /// <param name="sequences">The sequences to concatenate, or null.</param>
        /// <returns>The concatenated <see cref="DLSequence"/>.</returns>
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

        /// <summary>Create a <see cref="DLSequence"/> from a collection of elements.</summary>
        /// <param name="elements">The elements.</param>
        /// <returns>The new <see cref="DLSequence"/>.</returns>
        public static new DLSequence FromCollection(IReadOnlyCollection<Asn1Encodable> elements)
        {
            return elements.Count < 1 ? Empty : new DLSequence(elements);
        }

        /// <summary>Create a <see cref="DLSequence"/> holding a single element.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The new <see cref="DLSequence"/>.</returns>
        public static new DLSequence FromElement(Asn1Encodable element) => new DLSequence(element);

        /// <summary>Create a <see cref="DLSequence"/> holding two elements.</summary>
        /// <param name="element1">The first element.</param>
        /// <param name="element2">The second element.</param>
        /// <returns>The new <see cref="DLSequence"/>.</returns>
        public static new DLSequence FromElements(Asn1Encodable element1, Asn1Encodable element2) =>
            new DLSequence(element1, element2);

        /// <summary>Create a <see cref="DLSequence"/> from an array of elements.</summary>
        /// <param name="elements">The elements.</param>
        /// <returns>The new <see cref="DLSequence"/>.</returns>
        public static new DLSequence FromElements(Asn1Encodable[] elements)
        {
            if (elements == null)
                throw new ArgumentNullException(nameof(elements));

            return elements.Length < 1 ? Empty : new DLSequence(elements);
        }

        /// <summary>
        /// Create a <see cref="DLSequence"/> from an array of elements, or null if the array is null.
        /// </summary>
        /// <param name="elements">The elements, or null.</param>
        /// <returns>The new <see cref="DLSequence"/>, or null if <paramref name="elements"/> is null.</returns>
        public static new DLSequence FromElementsOptional(Asn1Encodable[] elements)
        {
            if (elements == null)
                return null;

            return elements.Length < 1 ? Empty : new DLSequence(elements);
        }

        /// <summary>Create a <see cref="DLSequence"/> with the elements of another sequence.</summary>
        /// <param name="sequence">The sequence.</param>
        /// <returns>The new <see cref="DLSequence"/>, or the argument itself if it is already of this type.</returns>
        public static new DLSequence FromSequence(Asn1Sequence sequence)
        {
            if (sequence is DLSequence dlSequence)
                return dlSequence;

            return WithElements(sequence.m_elements);
        }

        /// <summary>Create a <see cref="DLSequence"/> from the elements of a vector.</summary>
        /// <param name="elementVector">The vector of elements.</param>
        /// <returns>The new <see cref="DLSequence"/>.</returns>
        public static new DLSequence FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DLSequence(elementVector);
        }

        /// <summary>Create a <see cref="DLSequence"/> by applying a function to each element of the source.</summary>
        /// <param name="sequence">The source sequence.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="DLSequence"/>.</returns>
        public static new DLSequence Map(Asn1Sequence sequence, Func<Asn1Encodable, Asn1Encodable> func)
        {
            return sequence.Count < 1 ? Empty : new DLSequence(sequence.MapElements(func), clone: false);
        }

        /// <summary>Create a <see cref="DLSequence"/> by applying a function to each element of the source.</summary>
        /// <param name="ts">The source array.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="DLSequence"/>.</returns>
        public static new DLSequence Map<T>(T[] ts, Func<T, Asn1Encodable> func)
        {
            return ts.Length < 1 ? Empty : new DLSequence(CollectionUtilities.Map(ts, func), clone: false);
        }

        /// <summary>Create a <see cref="DLSequence"/> by applying a function to each element of the source.</summary>
        /// <param name="c">The source collection.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="DLSequence"/>.</returns>
        public static new DLSequence Map<T>(IReadOnlyCollection<T> c, Func<T, Asn1Encodable> func)
        {
            return c.Count < 1 ? Empty : new DLSequence(CollectionUtilities.Map(c, func), clone: false);
        }

        internal static new DLSequence WithElements(Asn1Encodable[] elements)
        {
            return elements.Length < 1 ? Empty : new DLSequence(elements, clone: false);
        }

        /// <summary>Create a new <see cref="DLSequence"/>.</summary>
        public DLSequence()
            : base()
        {
        }

        /// <summary>Create a new <see cref="DLSequence"/>.</summary>
        /// <param name="element">The element.</param>
        public DLSequence(Asn1Encodable element)
            : base(element)
        {
        }

        /// <summary>Create a new <see cref="DLSequence"/>.</summary>
        /// <param name="element1">The element 1.</param>
        /// <param name="element2">The element 2.</param>
        public DLSequence(Asn1Encodable element1, Asn1Encodable element2)
            : base(element1, element2)
        {
        }

        /// <summary>Create a new <see cref="DLSequence"/>.</summary>
        /// <param name="elements">The elements.</param>
        public DLSequence(params Asn1Encodable[] elements)
            : base(elements)
        {
        }

        /// <summary>Create a new <see cref="DLSequence"/>.</summary>
        /// <param name="elementVector">The element vector.</param>
        public DLSequence(Asn1EncodableVector elementVector)
            : base(elementVector)
        {
        }

        /// <summary>Create a new <see cref="DLSequence"/>.</summary>
        /// <param name="elements">The elements.</param>
        public DLSequence(IReadOnlyCollection<Asn1Encodable> elements)
            : base(elements)
        {
        }

        /// <summary>Create a new <see cref="DLSequence"/>.</summary>
        /// <param name="sequence">The sequence.</param>
        public DLSequence(Asn1Sequence sequence)
            : base(sequence)
        {
        }

        /// <summary>Create a new <see cref="DLSequence"/>.</summary>
        /// <param name="asn1Set">The asn 1 set.</param>
        public DLSequence(Asn1Set asn1Set)
            : base(asn1Set)
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

        internal override DerExternal ToAsn1External() => DLExternal.FromSequence(this);

        internal override Asn1Set ToAsn1Set() => new DLSet(false, m_elements);
    }
}
