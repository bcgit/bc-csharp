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

        internal override int EncodedLength(bool withID)
        {
            throw Platform.CreateNotImplementedException("DerTaggedObject.EncodedLength");
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
		{
			if (!IsEmpty())
			{
				byte[] bytes = obj.GetDerEncoded();

				if (explicitly)
				{
					asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.ContextSpecific, tagNo, bytes);
				}
				else
				{
					//
					// need to mark constructed types... (preserve Constructed tag)
					//
                    if (withID)
                    {
                        int flags = (bytes[0] & Asn1Tags.Constructed) | Asn1Tags.ContextSpecific;
                        asn1Out.WriteIdentifier(true, flags, tagNo);
                    }

                    asn1Out.Write(bytes, 1, bytes.Length - 1);
				}
			}
			else
			{
				asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.ContextSpecific, tagNo,
                    Asn1OctetString.EmptyOctets);
			}
		}
	}
}
