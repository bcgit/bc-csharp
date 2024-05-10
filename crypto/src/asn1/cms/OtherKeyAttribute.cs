using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class OtherKeyAttribute
        : Asn1Encodable
    {
        public static OtherKeyAttribute GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherKeyAttribute otherKeyAttribute)
                return otherKeyAttribute;
#pragma warning disable CS0618 // Type or member is obsolete
            return new OtherKeyAttribute(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static OtherKeyAttribute GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new OtherKeyAttribute(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private DerObjectIdentifier	keyAttrId;
        private Asn1Encodable		keyAttr;

        [Obsolete("Use 'GetInstance' instead")]
        public OtherKeyAttribute(
            Asn1Sequence seq)
        {
            keyAttrId = (DerObjectIdentifier) seq[0];
            keyAttr = seq[1];
        }

		public OtherKeyAttribute(
            DerObjectIdentifier	keyAttrId,
            Asn1Encodable		keyAttr)
        {
            this.keyAttrId = keyAttrId;
            this.keyAttr = keyAttr;
        }

		public DerObjectIdentifier KeyAttrId
		{
			get { return keyAttrId; }
		}

		public Asn1Encodable KeyAttr
		{
			get { return keyAttr; }
		}

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OtherKeyAttribute ::= Sequence {
         *     keyAttrId OBJECT IDENTIFIER,
         *     keyAttr ANY DEFINED BY keyAttrId OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
			return new DerSequence(keyAttrId, keyAttr);
        }
    }
}
