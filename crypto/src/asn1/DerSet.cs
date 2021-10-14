using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
	/**
	 * A Der encoded set object
	 */
	public class DerSet
		: Asn1Set
	{
		public static readonly DerSet Empty = new DerSet();

		public static DerSet FromVector(Asn1EncodableVector elementVector)
		{
            return elementVector.Count < 1 ? Empty : new DerSet(elementVector);
		}

		internal static DerSet FromVector(Asn1EncodableVector elementVector, bool needsSorting)
		{
            return elementVector.Count < 1 ? Empty : new DerSet(elementVector, needsSorting);
		}

		/**
		 * create an empty set
		 */
		public DerSet()
			: base()
		{
		}

		/**
		 * @param obj - a single object that makes up the set.
		 */
		public DerSet(Asn1Encodable element)
			: base(element)
		{
		}

		public DerSet(params Asn1Encodable[] elements)
			: base(elements)
		{
			Sort();
		}

		/**
		 * @param v - a vector of objects making up the set.
		 */
		public DerSet(Asn1EncodableVector elementVector)
			: this(elementVector, true)
		{
		}

		internal DerSet(Asn1EncodableVector	elementVector, bool needsSorting)
			: base(elementVector)
		{
			if (needsSorting)
			{
				Sort();
			}
		}

        internal override int EncodedLength(bool withID)
        {
            throw Platform.CreateNotImplementedException("DerSet.EncodedLength");
        }

        /*
		 * A note on the implementation:
		 * <p>
		 * As Der requires the constructed, definite-length model to
		 * be used for structured types, this varies slightly from the
		 * ASN.1 descriptions given. Rather than just outputing Set,
		 * we also have to specify Constructed, and the objects length.
		 */
        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (Count < 1)
            {
                asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.Set, Asn1OctetString.EmptyOctets);
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

            asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.Set, bytes, 0, length);

            Platform.Dispose(dOut);
        }
    }
}
