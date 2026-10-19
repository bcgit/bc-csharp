using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 SET with BER encoding.</summary>
    public class BerSet
        : DLSet
    {
        public static new readonly BerSet Empty = new BerSet();

        public static new BerSet FromCollection(IReadOnlyCollection<Asn1Encodable> elements)
        {
            return elements.Count < 1 ? Empty : new BerSet(elements);
        }

        public static new BerSet FromElement(Asn1Encodable element) => new BerSet(element);

        public static new BerSet FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new BerSet(elementVector);
        }

        public static new BerSet Map<T>(T[] ts, Func<T, Asn1Encodable> func)
        {
            return ts.Length < 1 ? Empty : new BerSet(isSorted: false, CollectionUtilities.Map(ts, func));
        }

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
