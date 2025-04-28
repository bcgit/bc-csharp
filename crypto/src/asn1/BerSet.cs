using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
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

        public BerSet()
            : base()
        {
        }

        public BerSet(Asn1Encodable element)
            : base(element)
        {
        }

        public BerSet(params Asn1Encodable[] elements)
            : base(elements)
        {
        }

        public BerSet(Asn1EncodableVector elementVector)
            : base(elementVector)
        {
        }

        public BerSet(IReadOnlyCollection<Asn1Encodable> elements)
            : base(elements)
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
