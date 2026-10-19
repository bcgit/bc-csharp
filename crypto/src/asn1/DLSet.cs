using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 SET with definite-length (DL) encoding.</summary>
    public class DLSet
        : DerSet
    {
        /// <summary>The empty <see cref="DLSet"/>.</summary>
        public static new readonly DLSet Empty = new DLSet();

        /// <summary>Create a <see cref="DLSet"/> from a collection of elements.</summary>
        /// <param name="elements">The elements.</param>
        /// <returns>The new <see cref="DLSet"/>.</returns>
        public static new DLSet FromCollection(IReadOnlyCollection<Asn1Encodable> elements)
        {
            return elements.Count < 1 ? Empty : new DLSet(elements);
        }

        /// <summary>Create a <see cref="DLSet"/> holding a single element.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The new <see cref="DLSet"/>.</returns>
        public static new DLSet FromElement(Asn1Encodable element) => new DLSet(element);

        /// <summary>Create a <see cref="DLSet"/> from the elements of a vector.</summary>
        /// <param name="elementVector">The vector of elements.</param>
        /// <returns>The new <see cref="DLSet"/>.</returns>
        public static new DLSet FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DLSet(elementVector);
        }

        /// <summary>Create a <see cref="DLSet"/> by applying a function to each element of the source.</summary>
        /// <param name="ts">The source array.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="DLSet"/>.</returns>
        public static new DLSet Map<T>(T[] ts, Func<T, Asn1Encodable> func)
        {
            return ts.Length < 1 ? Empty : new DLSet(isSorted: false, CollectionUtilities.Map(ts, func));
        }

        /// <summary>Create a <see cref="DLSet"/> by applying a function to each element of the source.</summary>
        /// <param name="c">The source collection.</param>
        /// <param name="func">The function to apply to each element.</param>
        /// <returns>The new <see cref="DLSet"/>.</returns>
        public static new DLSet Map<T>(IReadOnlyCollection<T> c, Func<T, Asn1Encodable> func)
        {
            return c.Count < 1 ? Empty : new DLSet(isSorted: false, CollectionUtilities.Map(c, func));
        }

        /// <summary>Create a new <see cref="DLSet"/>.</summary>
        public DLSet()
            : base()
        {
        }

        /// <summary>Create a new <see cref="DLSet"/>.</summary>
        /// <param name="element">The element.</param>
        public DLSet(Asn1Encodable element)
            : base(element)
        {
        }

        /// <summary>Create a new <see cref="DLSet"/>.</summary>
        /// <param name="elements">The elements.</param>
        public DLSet(params Asn1Encodable[] elements)
            : base(elements, doSort: false)
        {
        }

        /// <summary>Create a new <see cref="DLSet"/>.</summary>
        /// <param name="elementVector">The element vector.</param>
        public DLSet(Asn1EncodableVector elementVector)
            : base(elementVector, doSort: false)
        {
        }

        /// <summary>Create a new <see cref="DLSet"/>.</summary>
        /// <param name="elements">The elements.</param>
        public DLSet(IReadOnlyCollection<Asn1Encodable> elements)
            : base(elements, doSort: false)
        {
        }

        /// <summary>Create a new <see cref="DLSet"/>.</summary>
        /// <param name="sequence">The sequence.</param>
        public DLSet(Asn1Sequence sequence)
            : base(sequence)
        {
        }

        /// <summary>Create a new <see cref="DLSet"/>.</summary>
        /// <param name="asn1Set">The asn 1 set.</param>
        public DLSet(Asn1Set asn1Set)
            : base(asn1Set)
        {
        }

        internal DLSet(bool isSorted, Asn1Encodable[] elements)
            : base(isSorted, elements)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncoding(encoding);

            return new ConstructedDLEncoding(Asn1Tags.Universal, Asn1Tags.Set,
                Asn1OutputStream.GetContentsEncodings(Asn1OutputStream.EncodingDL, m_elements));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            return new ConstructedDLEncoding(tagClass, tagNo,
                Asn1OutputStream.GetContentsEncodings(Asn1OutputStream.EncodingDL, m_elements));
        }
    }
}
