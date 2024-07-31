using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
	* This class helps to support crossCerfificatePairs in a LDAP directory
	* according RFC 2587
	*
	* <pre>
	*     crossCertificatePairATTRIBUTE::={
	*       WITH SYNTAX   CertificatePair
	*       EQUALITY MATCHING RULE certificatePairExactMatch
	*       ID joint-iso-ccitt(2) ds(5) attributeType(4) crossCertificatePair(40)}
	* </pre>
	*
	* <blockquote> The forward elements of the crossCertificatePair attribute of a
	* CA's directory entry shall be used to store all, except self-issued
	* certificates issued to this CA. Optionally, the reverse elements of the
	* crossCertificatePair attribute, of a CA's directory entry may contain a
	* subset of certificates issued by this CA to other CAs. When both the forward
	* and the reverse elements are present in a single attribute value, issuer name
	* in one certificate shall match the subject name in the other and vice versa,
	* and the subject public key in one certificate shall be capable of verifying
	* the digital signature on the other certificate and vice versa.
	*
	* When a reverse element is present, the forward element value and the reverse
	* element value need not be stored in the same attribute value; in other words,
	* they can be stored in either a single attribute value or two attribute
	* values. </blockquote>
	*
	* <pre>
	*       CertificatePair ::= SEQUENCE {
	*         forward		[0]	Certificate OPTIONAL,
	*         reverse		[1]	Certificate OPTIONAL,
	*         -- at least one of the pair shall be present -- }
	* </pre>
	*/
    public class CertificatePair
		: Asn1Encodable
	{
        public static CertificatePair GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertificatePair certificatePair)
                return certificatePair;
            return new CertificatePair(Asn1Sequence.GetInstance(obj));
        }

        public static CertificatePair GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificatePair(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertificatePair GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificatePair(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private X509CertificateStructure m_forward, m_reverse;

        /**
		* Constructor from Asn1Sequence.
		* <p/>
		* The sequence is of type CertificatePair:
		* <p/>
		* <pre>
		*       CertificatePair ::= SEQUENCE {
		*         forward		[0]	Certificate OPTIONAL,
		*         reverse		[1]	Certificate OPTIONAL,
		*         -- at least one of the pair shall be present -- }
		* </pre>
		*
		* @param seq The ASN.1 sequence.
		*/
        private CertificatePair(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_forward = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, X509CertificateStructure.GetTagged);
            m_reverse = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, X509CertificateStructure.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            Validate();
        }

        /**
		* Constructor from a given details.
		*
		* @param forward Certificates issued to this CA.
		* @param reverse Certificates issued by this CA to other CAs.
		*/
        public CertificatePair(X509CertificateStructure forward, X509CertificateStructure reverse)
        {
            m_forward = forward;
			m_reverse = reverse;

			Validate();
		}

		/**
		* Produce an object suitable for an Asn1OutputStream.
		* <p/>
		* Returns:
		* <p/>
		* <pre>
		*       CertificatePair ::= SEQUENCE {
		*         forward		[0]	Certificate OPTIONAL,
		*         reverse		[1]	Certificate OPTIONAL,
		*         -- at least one of the pair shall be present -- }
		* </pre>
		*
		* @return a DERObject
		*/
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(true, 0, m_forward);
            v.AddOptionalTagged(true, 1, m_reverse);
            return new DerSequence(v);
        }

		/**
		* @return Returns the forward.
		*/
		public X509CertificateStructure Forward => m_forward;

		/**
		* @return Returns the reverse.
		*/
		public X509CertificateStructure Reverse => m_reverse;

        private void Validate()
		{
			if (m_forward == null && m_reverse == null)
				throw new ArgumentException("At least one of the pair shall be present");
		}
    }
}
