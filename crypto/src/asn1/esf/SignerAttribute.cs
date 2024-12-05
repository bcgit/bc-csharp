using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    public class SignerAttribute
		: Asn1Encodable
	{
        public static SignerAttribute GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SignerAttribute signerAttribute)
                return signerAttribute;
            return new SignerAttribute(Asn1Sequence.GetInstance(obj), dummy: true);
        }

        public static SignerAttribute GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignerAttribute(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SignerAttribute GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignerAttribute(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_claimedAttributes;
        private readonly AttributeCertificate m_certifiedAttributes;

        private SignerAttribute(Asn1Sequence seq, bool dummy)
		{
			Asn1TaggedObject taggedObject = Asn1TaggedObject.GetInstance(seq[0], Asn1Tags.ContextSpecific);
			if (taggedObject.TagNo == 0)
			{
				m_claimedAttributes = Asn1Sequence.GetInstance(taggedObject, true);
			}
			else if (taggedObject.TagNo == 1)
			{
				m_certifiedAttributes = AttributeCertificate.GetInstance(taggedObject, true);
			}
			else
			{
				throw new ArgumentException("illegal tag.", nameof(seq));
			}
		}

		public SignerAttribute(Asn1Sequence claimedAttributes)
		{
			m_claimedAttributes = claimedAttributes ?? throw new ArgumentNullException(nameof(claimedAttributes));
		}

		public SignerAttribute(AttributeCertificate certifiedAttributes)
		{
			m_certifiedAttributes = certifiedAttributes ?? throw new ArgumentNullException(nameof(certifiedAttributes));
		}

		public virtual Asn1Sequence ClaimedAttributes => m_claimedAttributes;

		public virtual AttributeCertificate CertifiedAttributes => m_certifiedAttributes;

		/**
		*
		* <pre>
		*  SignerAttribute ::= SEQUENCE OF CHOICE {
		*      claimedAttributes   [0] ClaimedAttributes,
		*      certifiedAttributes [1] CertifiedAttributes }
		*
		*  ClaimedAttributes ::= SEQUENCE OF Attribute
		*  CertifiedAttributes ::= AttributeCertificate -- as defined in RFC 3281: see clause 4.1.
		* </pre>
		*/
		public override Asn1Object ToAsn1Object()
		{
			return m_claimedAttributes != null
				?	new DerSequence(new DerTaggedObject(0, m_claimedAttributes))
				:	new DerSequence(new DerTaggedObject(1, m_certifiedAttributes));
		}
	}
}
