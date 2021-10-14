using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
	public class DerSequence
		: Asn1Sequence
	{
		public static readonly DerSequence Empty = new DerSequence();

		public static DerSequence FromVector(Asn1EncodableVector elementVector)
		{
            return elementVector.Count < 1 ? Empty : new DerSequence(elementVector);
		}

		/**
		 * create an empty sequence
		 */
		public DerSequence()
			: base()
		{
		}

		/**
		 * create a sequence containing one object
		 */
		public DerSequence(Asn1Encodable element)
			: base(element)
		{
		}

		public DerSequence(params Asn1Encodable[] elements)
            : base(elements)
		{
		}

		/**
		 * create a sequence containing a vector of objects.
		 */
		public DerSequence(Asn1EncodableVector elementVector)
            : base(elementVector)
		{
		}

        /*
		 * A note on the implementation:
		 * <p>
		 * As Der requires the constructed, definite-length model to
		 * be used for structured types, this varies slightly from the
		 * ASN.1 descriptions given. Rather than just outputing Sequence,
		 * we also have to specify Constructed, and the objects length.
		 */
        internal override void Encode(Asn1OutputStream asn1Out)
        {
            if (Count < 1)
            {
                asn1Out.WriteEncoded(Asn1Tags.Sequence | Asn1Tags.Constructed, Asn1OctetString.EmptyOctets);
                return;
            }

            // TODO Intermediate buffer could be avoided if we could calculate expected length
            MemoryStream bOut = new MemoryStream();
            Asn1OutputStream dOut = Asn1OutputStream.Create(bOut, Der);
            dOut.WriteElements(elements);
            dOut.Flush();

#if PORTABLE
            byte[] bytes = bOut.ToArray();
            int length = bytes.Length;
#else
            byte[] bytes = bOut.GetBuffer();
            int length = (int)bOut.Position;
#endif

            asn1Out.WriteEncoded(Asn1Tags.Sequence | Asn1Tags.Constructed, bytes, 0, length);

            Platform.Dispose(dOut);
        }
    }
}
