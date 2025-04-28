using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    public class DLSet
        : DerSet
    {
        public static new readonly DLSet Empty = new DLSet();

        public static new DLSet FromCollection(IReadOnlyCollection<Asn1Encodable> elements)
        {
            return elements.Count < 1 ? Empty : new DLSet(elements);
        }

        public static new DLSet FromElement(Asn1Encodable element) => new DLSet(element);

        public static new DLSet FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DLSet(elementVector);
        }

        public static new DLSet Map<T>(T[] ts, Func<T, Asn1Encodable> func)
        {
            return ts.Length < 1 ? Empty : new DLSet(isSorted: false, CollectionUtilities.Map(ts, func));
        }

        public static new DLSet Map<T>(IReadOnlyCollection<T> c, Func<T, Asn1Encodable> func)
        {
            return c.Count < 1 ? Empty : new DLSet(isSorted: false, CollectionUtilities.Map(c, func));
        }

        public DLSet()
            : base()
        {
        }

        public DLSet(Asn1Encodable element)
            : base(element)
        {
        }

        public DLSet(params Asn1Encodable[] elements)
            : base(elements, doSort: false)
        {
        }

        public DLSet(Asn1EncodableVector elementVector)
            : base(elementVector, doSort: false)
        {
        }

        public DLSet(IReadOnlyCollection<Asn1Encodable> elements)
            : base(elements, doSort: false)
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
