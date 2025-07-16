using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ess
{
    public class SigningCertificate
		: Asn1Encodable
	{
        public static SigningCertificate GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is SigningCertificate signingCertificate)
                return signingCertificate;
#pragma warning disable CS0618 // Type or member is obsolete
            return new SigningCertificate(Asn1Sequence.GetInstance(o));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static SigningCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SigningCertificate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static SigningCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SigningCertificate(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1Sequence m_certs;
        private readonly Asn1Sequence m_policies;

        [Obsolete("Use 'GetInstance' instead")]
        public SigningCertificate(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certs = Asn1Sequence.GetInstance(seq[pos++]);
            m_policies = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

		public SigningCertificate(EssCertID essCertID)
		{
			m_certs = new DerSequence(essCertID);
		}

        public EssCertID[] GetCerts() => m_certs.MapElements(EssCertID.GetInstance);

        public PolicyInformation[] GetPolicies() => m_policies?.MapElements(PolicyInformation.GetInstance);

        /**
		 * The definition of SigningCertificate is
		 * <pre>
		 * SigningCertificate ::=  SEQUENCE {
		 *      certs        SEQUENCE OF EssCertID,
		 *      policies     SEQUENCE OF PolicyInformation OPTIONAL
		 * }
		 * </pre>
		 * id-aa-signingCertificate OBJECT IDENTIFIER ::= { iso(1)
		 *  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
		 *  smime(16) id-aa(2) 12 }
		 */
        public override Asn1Object ToAsn1Object()
        {
            return m_policies == null
                ?  DerSequence.FromElement(m_certs)
                :  DerSequence.FromElements(m_certs, m_policies);
        }
    }
}
