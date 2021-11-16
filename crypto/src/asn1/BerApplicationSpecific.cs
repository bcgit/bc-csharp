using System;

namespace Org.BouncyCastle.Asn1
{
	public class BerApplicationSpecific
		: DerApplicationSpecific
	{
        /**
         * Create an application specific object with an explicit tag
         *
         * @param tagNo the tag number for this object.
         * @param baseEncodable the object to be contained.
         */
        public BerApplicationSpecific(int tagNo, Asn1Encodable baseEncodable)
            : this(true, tagNo, baseEncodable)
        {
        }

        /**
         * Create an application specific object with the tagging style given by the value of explicit.
         *
         * @param explicit true if the object is explicitly tagged.
         * @param tagNo the tag number for this object.
         * @param baseEncodable the object to be contained.
         */
        public BerApplicationSpecific(bool isExplicit, int tagNo, Asn1Encodable baseEncodable)
            : base(new BerTaggedObject(isExplicit, Asn1Tags.Application, tagNo, baseEncodable))
        {
        }

        /**
         * Create an application specific object which is marked as constructed
         *
         * @param tagNo the tag number for this object.
         * @param contentsElements the objects making up the application specific object.
         */
        public BerApplicationSpecific(int tagNo, Asn1EncodableVector contentsElements)
            : base(new BerTaggedObject(false, Asn1Tags.Application, tagNo, BerSequence.FromVector(contentsElements)))
        {
        }

        internal BerApplicationSpecific(Asn1TaggedObject taggedObject)
            : base(taggedObject)
        {
        }
	}
}
