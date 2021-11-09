using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    internal class DLSequence
        : DerSequence
    {
        internal static new readonly DLSequence Empty = new DLSequence();

        internal static new DLSequence FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DLSequence(elementVector);
        }

        /**
		 * create an empty sequence
		 */
        internal DLSequence()
            : base()
        {
        }

        /**
		 * create a sequence containing one object
		 */
        internal DLSequence(Asn1Encodable element)
            : base(element)
        {
        }

        internal DLSequence(params Asn1Encodable[] elements)
            : base(elements)
        {
        }

        /**
		 * create a sequence containing a vector of objects.
		 */
        internal DLSequence(Asn1EncodableVector elementVector)
            : base(elementVector)
        {
        }

        internal DLSequence(Asn1Encodable[] elements, bool clone)
            : base(elements, clone)
        {
        }

        internal override int EncodedLength(bool withID)
        {
            throw Platform.CreateNotImplementedException("DLSequence.EncodedLength");
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
                asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.Sequence, Asn1OctetString.EmptyOctets);
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

            asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.Sequence, bytes, 0, length);

            Platform.Dispose(dOut);
        }

        internal override Asn1Set ToAsn1Set()
        {
            return new DLSet(false, elements);
        }
    }
}
