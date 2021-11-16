using System;

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
		 * create an implicitly tagged object that contains a zero
		 * length sequence.
		 */
        [Obsolete("Will be removed")]
        public BerTaggedObject(int tagNo)
            : base(false, tagNo, BerSequence.Empty)
        {
        }

        /**
		 * @param tagNo the tag number for this object.
		 * @param obj the tagged object.
		 */
        public BerTaggedObject(int tagNo, Asn1Encodable obj)
			: base(true, tagNo, obj)
		{
		}

        public BerTaggedObject(int tagClass, int tagNo, Asn1Encodable obj)
            : base(true, tagClass, tagNo, obj)
        {
        }

        /**
		 * @param isExplicit true if an explicitly tagged object.
		 * @param tagNo the tag number for this object.
		 * @param obj the tagged object.
		 */
        public BerTaggedObject(bool isExplicit, int tagNo, Asn1Encodable obj)
			: base(isExplicit, tagNo, obj)
		{
		}

        public BerTaggedObject(bool isExplicit, int tagClass, int tagNo, Asn1Encodable obj)
            : base(isExplicit, tagClass, tagNo, obj)
        {
        }

        internal BerTaggedObject(int explicitness, int tagClass, int tagNo, Asn1Encodable obj)
            : base(explicitness, tagClass, tagNo, obj)
        {
        }

        internal override string Asn1Encoding
        {
            get { return Ber; }
        }

        internal override bool EncodeConstructed(int encoding)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.EncodeConstructed(encoding);

            return IsExplicit() || GetBaseObject().ToAsn1Object().EncodeConstructed(encoding);
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.EncodedLength(encoding, withID);

            Asn1Object baseObject = GetBaseObject().ToAsn1Object();
            bool withBaseID = IsExplicit();

            int length = baseObject.EncodedLength(encoding, withBaseID);

            if (withBaseID)
            {
                length += 3;
            }

            length += withID ? Asn1OutputStream.GetLengthOfIdentifier(TagNo) : 0;

            return length;
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
		{
            if (Asn1OutputStream.EncodingBer != asn1Out.Encoding)
            {
                base.Encode(asn1Out, withID);
                return;
            }

            Asn1Object baseObject = GetBaseObject().ToAsn1Object();
            bool withBaseID = IsExplicit();

            if (withID)
            {
                int flags = TagClass;
                if (withBaseID || baseObject.EncodeConstructed(asn1Out.Encoding))
                {
                    flags |= Asn1Tags.Constructed;
                }

                asn1Out.WriteIdentifier(true, flags, TagNo);
            }

            if (withBaseID)
            {
                asn1Out.WriteByte(0x80);
                baseObject.Encode(asn1Out, true);
                asn1Out.WriteByte(0x00);
                asn1Out.WriteByte(0x00);
            }
            else
            {
                baseObject.Encode(asn1Out, false);
            }
		}

        internal override Asn1Sequence RebuildConstructed(Asn1Object asn1Object)
        {
            return new BerSequence(asn1Object);
        }

        internal override Asn1TaggedObject ReplaceTag(int tagClass, int tagNo)
        {
            return new BerTaggedObject(explicitness, tagClass, tagNo, obj);
        }
    }
}
