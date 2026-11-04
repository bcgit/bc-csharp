using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    public class DerSet
        : Asn1Set
    {
        public static readonly DerSet Empty = new DerSet();

        public static DerSet FromCollection(IReadOnlyCollection<Asn1Encodable> elements)
        {
            return elements.Count < 1 ? Empty : new DerSet(elements);
        }

        public static DerSet FromElement(Asn1Encodable element) => new DerSet(element);

        public static DerSet FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DerSet(elementVector);
        }

        public static DerSet Map<T>(T[] ts, Func<T, Asn1Encodable> func)
        {
            return ts.Length < 1 ? Empty : WithElementsUnshared(CollectionUtilities.Map(ts, func));
        }

        public static DerSet Map<T>(IReadOnlyCollection<T> c, Func<T, Asn1Encodable> func)
        {
            return c.Count < 1 ? Empty : WithElementsUnshared(CollectionUtilities.Map(c, func));
        }

        /// <summary>Create a DER set that uses <paramref name="elements"/> directly, without copying.</summary>
        /// <remarks>
        /// The array is sorted in place, so it must not be shared: the caller gives up the array, which must not
        /// also be another object's backing array (e.g. a sequence's elements).
        /// </remarks>
        internal static DerSet WithElementsUnshared(Asn1Encodable[] elements)
        {
            if (elements.Length < 1)
                return Empty;

            var sortedDerEncodings = elements.Length > 1 ? SortElements(elements) : null;
            return new DerSet(elements, sortedDerEncodings);
        }

        public DerSet()
            : base()
        {
        }

        public DerSet(Asn1Encodable element)
            : base(element)
        {
        }

        public DerSet(params Asn1Encodable[] elements)
            : base(elements, doSort: true)
        {
        }

        private protected DerSet(Asn1Encodable[] elements, bool doSort)
            : base(elements, doSort)
        {
        }

        public DerSet(Asn1EncodableVector elementVector)
            : base(elementVector, doSort: true)
        {
        }

        private protected DerSet(Asn1EncodableVector elementVector, bool doSort)
            : base(elementVector, doSort)
        {
        }

        public DerSet(IReadOnlyCollection<Asn1Encodable> elements)
            : base(elements, doSort: true)
        {
        }

        public DerSet(Asn1Sequence sequence)
            : base(element: sequence)
        {
        }

        public DerSet(Asn1Set asn1Set)
            : base(element: asn1Set)
        {
        }

        private protected DerSet(IReadOnlyCollection<Asn1Encodable> elements, bool doSort)
            : base(elements, doSort)
        {
        }

        private protected DerSet(Asn1Encodable[] elements, DerEncoding[] sortedDerEncodings)
            : base(elements, sortedDerEncodings)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new ConstructedDLEncoding(Asn1Tags.Universal, Asn1Tags.Set, GetSortedDerEncodings());
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new ConstructedDLEncoding(tagClass, tagNo, GetSortedDerEncodings());
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new ConstructedDerEncoding(Asn1Tags.Universal, Asn1Tags.Set, GetSortedDerEncodings());
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new ConstructedDerEncoding(tagClass, tagNo, GetSortedDerEncodings());
        }

        private DerEncoding[] GetSortedDerEncodings() =>
            Objects.EnsureSingletonInitialized(ref m_sortedDerEncodings, m_elements, CreateSortedDerEncodings);

        private static DerEncoding[] CreateSortedDerEncodings(Asn1Encodable[] elements)
        {
            var derEncodings = Asn1OutputStream.GetContentsEncodingsDer(elements);
            if (derEncodings.Length > 1)
            {
                Array.Sort(derEncodings);
            }
            return derEncodings;
        }
    }
}
