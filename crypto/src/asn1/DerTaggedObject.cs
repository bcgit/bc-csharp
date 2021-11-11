using System;

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
        private int m_contentsLengthDer = -1;

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

        internal override bool EncodeConstructed(int encoding)
        {
            encoding = Asn1OutputStream.EncodingDer;

            return IsExplicit() || GetBaseObject().ToAsn1Object().EncodeConstructed(encoding);
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            encoding = Asn1OutputStream.EncodingDer;

            Asn1Object baseObject = GetBaseObject().ToAsn1Object();
            bool withBaseID = IsExplicit();

            int length = GetContentsLengthDer(baseObject, withBaseID);

            if (withBaseID)
            {
                length += Asn1OutputStream.GetLengthOfDL(length);
            }

            length += withID ? Asn1OutputStream.GetLengthOfIdentifier(TagNo) : 0;

            return length;
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            asn1Out = asn1Out.GetDerSubStream();

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
                asn1Out.WriteDL(GetContentsLengthDer(baseObject, true));
            }

            baseObject.Encode(asn1Out, withBaseID);
        }

        internal override Asn1Sequence RebuildConstructed(Asn1Object asn1Object)
        {
            return new DerSequence(asn1Object);
        }

        private int GetContentsLengthDer(Asn1Object baseObject, bool withBaseID)
        {
            if (m_contentsLengthDer < 0)
            {
                m_contentsLengthDer = baseObject.EncodedLength(Asn1OutputStream.EncodingDer, withBaseID);
            }
            return m_contentsLengthDer;
        }
    }
}
