using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    internal class DLSet
        : DerSet
    {
        internal static new readonly DLSet Empty = new DLSet();

        internal static new DLSet FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DLSet(elementVector);
        }

        /**
         * create an empty set
         */
        internal DLSet()
            : base()
        {
        }

        /**
         * create a set containing one object
         */
        internal DLSet(Asn1Encodable element)
            : base(element)
        {
        }

        internal DLSet(params Asn1Encodable[] elements)
            : base(elements, false)
        {
        }

        /**
         * create a set containing a vector of objects.
         */
        internal DLSet(Asn1EncodableVector elementVector)
            : base(elementVector, false)
        {
        }

        internal DLSet(bool isSorted, Asn1Encodable[] elements)
            : base(isSorted, elements)
        {
        }

        internal override int EncodedLength(bool withID)
        {
            throw Platform.CreateNotImplementedException("DLSet.EncodedLength");
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (asn1Out.IsDer)
            {
                base.Encode(asn1Out, withID);
                return;
            }

            if (Count < 1)
            {
                asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.Set, Asn1OctetString.EmptyOctets);
                return;
            }

            // TODO Intermediate buffer could be avoided if we could calculate expected length
            MemoryStream bOut = new MemoryStream();
            // TODO Once DLOutputStream exists, this should create one
            Asn1OutputStream dOut = Asn1OutputStream.Create(bOut);
            dOut.WriteElements(elements);
            dOut.FlushInternal();

#if PORTABLE
            byte[] bytes = bOut.ToArray();
            int length = bytes.Length;
#else
            byte[] bytes = bOut.GetBuffer();
            int length = (int)bOut.Position;
#endif

            asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.Set, bytes, 0, length);

            Platform.Dispose(dOut);
        }
    }
}
