using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
	/**
	 * DER TaggedObject - in ASN.1 notation this is any object preceded by
	 * a [n] where n is some number - these are assumed to follow the construction
	 * rules (as with sequences).
	 */
	public class DerTaggedObject
		: Asn1TaggedObject
	{
		/**
		 * @param tagNo the tag number for this object.
		 * @param obj the tagged object.
		 */
		public DerTaggedObject(
			int				tagNo,
			Asn1Encodable	obj)
			: base(tagNo, obj)
		{
		}

		/**
		 * @param explicitly true if an explicitly tagged object.
		 * @param tagNo the tag number for this object.
		 * @param obj the tagged object.
		 */
		public DerTaggedObject(
			bool			explicitly,
			int				tagNo,
			Asn1Encodable	obj)
			: base(explicitly, tagNo, obj)
		{
		}

		/**
		 * create an implicitly tagged object that contains a zero
		 * length sequence.
		 */
		public DerTaggedObject(
			int tagNo)
			: base(false, tagNo, DerSequence.Empty)
		{
		}

        internal override string Asn1Encoding
        {
            get { return Der; }
        }

        internal override bool EncodeConstructed()
        {
            throw Platform.CreateNotImplementedException("DerTaggedObject.EncodeConstructed");

            //return IsExplicit() || obj.ToAsn1Object().ToDerObject().EncodeConstructed();
        }

        internal override int EncodedLength(bool withID)
        {
            throw Platform.CreateNotImplementedException("DerTaggedObject.EncodedLength");
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            byte[] bytes = obj.GetDerEncoded();

            if (explicitly)
            {
                asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | TagClass, TagNo, bytes);
            }
            else
            {
                int tagHdr = bytes[0], tagLen = 1;
                if ((tagHdr & 0x1F) == 0x1F)
                {
                    while ((bytes[tagLen++] & 0x80) != 0)
                    {
                    }
                }

                if (withID)
                {
                    int flags = (tagHdr & Asn1Tags.Constructed) | TagClass;

                    asn1Out.WriteIdentifier(true, flags, TagNo);
                }

                asn1Out.Write(bytes, tagLen, bytes.Length - tagLen);
            }
        }

        internal override Asn1Sequence RebuildConstructed(Asn1Object asn1Object)
        {
            return new DerSequence(asn1Object);
        }
    }
}
