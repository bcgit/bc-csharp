using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 SET with BER encoding.</summary>
    public class BerSet
        : DLSet
    {
        /// <summary>The empty <see cref="BerSet"/>.</summary>
        public static new readonly BerSet Empty = new BerSet();

        /// <summary>Create a <see cref="BerSet"/> from a collection of elements.</summary>
        /// <param name="elements">The elements.</param>
        /// <returns>The new <see cref="BerSet"/>.</returns>
        public static new BerSet FromCollection(IReadOnlyCollection<Asn1Encodable> elements)
        {
            return elements.Count < 1 ? Empty : new BerSet(elements);
        }

        /// <summary>Create a <see cref="BerSet"/> holding a single element.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The new <see cref="BerSet"/>.</returns>
        public static new BerSet FromElement(Asn1Encodable element) => new BerSet(element);

        /// <summary>Create a <see cref="BerSet"/> from the elements of a vector.</summary>
        /// <param name="elementVector">The vector of elements.</param>
        /// <returns>The new <see cref="BerSet"/>.</returns>
        public static new BerSet FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new BerSet(elementVector);
        }

        /// <summary>Create a <see cref="BerSet"/> by applying a function to each element of the source.</summary>
        /// <param name="ts">The source array.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="BerSet"/>.</returns>
        public static new BerSet Map<T>(T[] ts, Func<T, Asn1Encodable> func)
        {
            return ts.Length < 1 ? Empty : new BerSet(isSorted: false, CollectionUtilities.Map(ts, func));
        }

        /// <summary>Create a <see cref="BerSet"/> by applying a function to each element of the source.</summary>
        /// <param name="c">The source collection.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="BerSet"/>.</returns>
        public static new BerSet Map<T>(IReadOnlyCollection<T> c, Func<T, Asn1Encodable> func)
        {
            return c.Count < 1 ? Empty : new BerSet(isSorted: false, CollectionUtilities.Map(c, func));
        }

        /// <summary>Create a new <see cref="BerSet"/>.</summary>
        public BerSet()
            : base()
        {
        }

        /// <summary>Create a new <see cref="BerSet"/>.</summary>
        /// <param name="element">The element.</param>
        public BerSet(Asn1Encodable element)
            : base(element)
        {
        }

        /// <summary>Create a new <see cref="BerSet"/>.</summary>
        /// <param name="elements">The elements.</param>
        public BerSet(params Asn1Encodable[] elements)
            : base(elements)
        {
        }

        /// <summary>Create a new <see cref="BerSet"/>.</summary>
        /// <param name="elementVector">The element vector.</param>
        public BerSet(Asn1EncodableVector elementVector)
            : base(elementVector)
        {
        }

        /// <summary>Create a new <see cref="BerSet"/>.</summary>
        /// <param name="elements">The elements.</param>
        public BerSet(IReadOnlyCollection<Asn1Encodable> elements)
            : base(elements)
        {
        }

        /// <summary>Create a new <see cref="BerSet"/>.</summary>
        /// <param name="sequence">The sequence.</param>
        public BerSet(Asn1Sequence sequence)
            : base(sequence)
        {
        }

        /// <summary>Create a new <see cref="BerSet"/>.</summary>
        /// <param name="asn1Set">The asn 1 set.</param>
        public BerSet(Asn1Set asn1Set)
            : base(asn1Set)
        {
        }

        internal BerSet(bool isSorted, Asn1Encodable[] elements)
            : base(isSorted, elements)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.GetEncoding(encoding);

            return new ConstructedILEncoding(Asn1Tags.Universal, Asn1Tags.Set,
                Asn1OutputStream.GetContentsEncodings(encoding, m_elements));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            return new ConstructedILEncoding(tagClass, tagNo,
                Asn1OutputStream.GetContentsEncodings(encoding, m_elements));
        }
    }
}
