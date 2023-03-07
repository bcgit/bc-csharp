using System;

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
            : base(elements, true)
        {
        }

        internal DerSet(Asn1Encodable[] elements, bool doSort)
			: base(elements, doSort)
		{
		}

		/**
		 * @param v - a vector of objects making up the set.
		 */
		public DerSet(Asn1EncodableVector elementVector)
			: base(elementVector, true)
		{
		}

		internal DerSet(Asn1EncodableVector	elementVector, bool doSort)
			: base(elementVector, doSort)
		{
		}

        internal DerSet(bool isSorted, Asn1Encodable[] elements)
            : base(isSorted, elements)
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

        private DerEncoding[] GetSortedDerEncodings()
        {
            return Objects.EnsureSingletonInitialized(ref m_sortedDerEncodings, m_elements, CreateSortedDerEncodings);
        }

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
