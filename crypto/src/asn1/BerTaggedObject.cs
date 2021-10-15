using System;
using System.Collections;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
	/**
	 * BER TaggedObject - in ASN.1 notation this is any object preceded by
	 * a [n] where n is some number - these are assumed to follow the construction
	 * rules (as with sequences).
	 */
	public class BerTaggedObject
		: DerTaggedObject
	{
		/**
		 * @param tagNo the tag number for this object.
		 * @param obj the tagged object.
		 */
		public BerTaggedObject(
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
		public BerTaggedObject(
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
		public BerTaggedObject(
			int tagNo)
			: base(false, tagNo, BerSequence.Empty)
		{
		}

        internal override int EncodedLength(bool withID)
        {
            throw Platform.CreateNotImplementedException("BerTaggedObject.EncodedLength");
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
		{
			if (asn1Out.IsBer)
			{
                if (withID)
                {
                    asn1Out.WriteIdentifier(true, Asn1Tags.Constructed | Asn1Tags.ContextSpecific, tagNo);
                }

                asn1Out.WriteByte(0x80);

				if (!IsEmpty())
				{
					if (!explicitly)
					{
						IEnumerable eObj;
						if (obj is Asn1OctetString)
						{
							if (obj is BerOctetString)
							{
								eObj = (BerOctetString) obj;
							}
							else
							{
								Asn1OctetString octs = (Asn1OctetString)obj;
								eObj = new BerOctetString(octs.GetOctets());
							}
						}
						else if (obj is Asn1Sequence)
						{
							eObj = (Asn1Sequence) obj;
						}
						else if (obj is Asn1Set)
						{
							eObj = (Asn1Set) obj;
						}
						else
						{
							throw Platform.CreateNotImplementedException(Platform.GetTypeName(obj));
						}

						foreach (Asn1Encodable o in eObj)
						{
							asn1Out.WritePrimitive(o.ToAsn1Object(), true);
						}
					}
					else
					{
						asn1Out.WritePrimitive(obj.ToAsn1Object(), true);
					}
				}

				asn1Out.WriteByte(0x00);
				asn1Out.WriteByte(0x00);
			}
			else
			{
				base.Encode(asn1Out, withID);
			}
		}
	}
}
