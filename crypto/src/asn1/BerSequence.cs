using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 SEQUENCE with BER encoding.</summary>
    public class BerSequence
        : DLSequence
    {
        /// <summary>The empty <see cref="BerSequence"/>.</summary>
        public static new readonly BerSequence Empty = new BerSequence();

        /// <summary>
        /// Create a <see cref="BerSequence"/> holding the elements of all the given sequences, in order.
        /// </summary>
        /// <param name="sequences">The sequences to concatenate, or null.</param>
        /// <returns>The concatenated <see cref="BerSequence"/>.</returns>
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

        /// <summary>Create a <see cref="BerSequence"/> from a collection of elements.</summary>
        /// <param name="elements">The elements.</param>
        /// <returns>The new <see cref="BerSequence"/>.</returns>
        public static new BerSequence FromCollection(IReadOnlyCollection<Asn1Encodable> elements)
        {
            return elements.Count < 1 ? Empty : new BerSequence(elements);
        }

        /// <summary>Create a <see cref="BerSequence"/> holding a single element.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The new <see cref="BerSequence"/>.</returns>
        public static new BerSequence FromElement(Asn1Encodable element) => new BerSequence(element);

        /// <summary>Create a <see cref="BerSequence"/> holding two elements.</summary>
        /// <param name="element1">The first element.</param>
        /// <param name="element2">The second element.</param>
        /// <returns>The new <see cref="BerSequence"/>.</returns>
        public static new BerSequence FromElements(Asn1Encodable element1, Asn1Encodable element2) =>
            new BerSequence(element1, element2);

        /// <summary>Create a <see cref="BerSequence"/> from an array of elements.</summary>
        /// <param name="elements">The elements.</param>
        /// <returns>The new <see cref="BerSequence"/>.</returns>
        public static new BerSequence FromElements(Asn1Encodable[] elements)
        {
            if (elements == null)
                throw new ArgumentNullException(nameof(elements));

            return elements.Length < 1 ? Empty : new BerSequence(elements);
        }

        /// <summary>
        /// Create a <see cref="BerSequence"/> from an array of elements, or null if the array is null.
        /// </summary>
        /// <param name="elements">The elements, or null.</param>
        /// <returns>The new <see cref="BerSequence"/>, or null if <paramref name="elements"/> is null.</returns>
        public static new BerSequence FromElementsOptional(Asn1Encodable[] elements)
        {
            if (elements == null)
                return null;

            return elements.Length < 1 ? Empty : new BerSequence(elements);
        }

        /// <summary>Create a <see cref="BerSequence"/> with the elements of another sequence.</summary>
        /// <param name="sequence">The sequence.</param>
        /// <returns>The new <see cref="BerSequence"/>, or the argument itself if it is already of this type.</returns>
        public static new BerSequence FromSequence(Asn1Sequence sequence)
        {
            if (sequence is BerSequence berSequence)
                return berSequence;

            return WithElements(sequence.m_elements);
        }

        /// <summary>Create a <see cref="BerSequence"/> from the elements of a vector.</summary>
        /// <param name="elementVector">The vector of elements.</param>
        /// <returns>The new <see cref="BerSequence"/>.</returns>
        public static new BerSequence FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new BerSequence(elementVector);
        }

        /// <summary>Create a <see cref="BerSequence"/> by applying a function to each element of the source.</summary>
        /// <param name="sequence">The source sequence.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="BerSequence"/>.</returns>
        public static new BerSequence Map(Asn1Sequence sequence, Func<Asn1Encodable, Asn1Encodable> func)
        {
            return sequence.Count < 1 ? Empty : new BerSequence(sequence.MapElements(func), clone: false);
        }

        /// <summary>Create a <see cref="BerSequence"/> by applying a function to each element of the source.</summary>
        /// <param name="ts">The source array.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="BerSequence"/>.</returns>
        public static new BerSequence Map<T>(T[] ts, Func<T, Asn1Encodable> func)
        {
            return ts.Length < 1 ? Empty : new BerSequence(CollectionUtilities.Map(ts, func), clone: false);
        }

        /// <summary>Create a <see cref="BerSequence"/> by applying a function to each element of the source.</summary>
        /// <param name="c">The source collection.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="BerSequence"/>.</returns>
        public static new BerSequence Map<T>(IReadOnlyCollection<T> c, Func<T, Asn1Encodable> func)
        {
            return c.Count < 1 ? Empty : new BerSequence(CollectionUtilities.Map(c, func), clone: false);
        }

        internal static new BerSequence WithElements(Asn1Encodable[] elements)
        {
            return elements.Length < 1 ? Empty : new BerSequence(elements, clone: false);
        }

        /// <summary>Create a new <see cref="BerSequence"/>.</summary>
        public BerSequence()
            : base()
        {
        }

        /// <summary>Create a new <see cref="BerSequence"/>.</summary>
        /// <param name="element">The element.</param>
        public BerSequence(Asn1Encodable element)
            : base(element)
        {
        }

        /// <summary>Create a new <see cref="BerSequence"/>.</summary>
        /// <param name="element1">The element 1.</param>
        /// <param name="element2">The element 2.</param>
        public BerSequence(Asn1Encodable element1, Asn1Encodable element2)
            : base(element1, element2)
        {
        }

        /// <summary>Create a new <see cref="BerSequence"/>.</summary>
        /// <param name="elements">The elements.</param>
        public BerSequence(params Asn1Encodable[] elements)
            : base(elements)
        {
        }

        /// <summary>Create a new <see cref="BerSequence"/>.</summary>
        /// <param name="elementVector">The element vector.</param>
        public BerSequence(Asn1EncodableVector elementVector)
            : base(elementVector)
        {
        }

        /// <summary>Create a new <see cref="BerSequence"/>.</summary>
        /// <param name="elements">The elements.</param>
        public BerSequence(IReadOnlyCollection<Asn1Encodable> elements)
            : base(elements)
        {
        }

        /// <summary>Create a new <see cref="BerSequence"/>.</summary>
        /// <param name="sequence">The sequence.</param>
        public BerSequence(Asn1Sequence sequence)
            : base(sequence)
        {
        }

        /// <summary>Create a new <see cref="BerSequence"/>.</summary>
        /// <param name="asn1Set">The asn 1 set.</param>
        public BerSequence(Asn1Set asn1Set)
            : base(asn1Set)
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

        internal override DerBitString ToAsn1BitString() => new BerBitString(GetConstructedBitStrings());

        // TODO[asn1] There is currently no BerExternal (or Asn1External)
        internal override DerExternal ToAsn1External() => DLExternal.FromSequence(this);

        internal override Asn1OctetString ToAsn1OctetString() => new BerOctetString(GetConstructedOctetStrings());

        internal override Asn1Set ToAsn1Set() => new BerSet(false, m_elements);
    }
}
