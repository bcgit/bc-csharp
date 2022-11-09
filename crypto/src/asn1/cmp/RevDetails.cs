using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     * RevDetails ::= SEQUENCE {
     *          certDetails         CertTemplate,
     *          -- allows requester to specify as much as they can about
     *          -- the cert. for which revocation is requested
     *          -- (e.g., for cases in which serialNumber is not available)
     *          crlEntryDetails     Extensions       OPTIONAL
     *          -- requested crlEntryExtensions
     *      }
     * </pre>
     */
    public class RevDetails
		: Asn1Encodable
	{
        public static RevDetails GetInstance(object obj)
        {
			if (obj is RevDetails revDetails)
				return revDetails;

			if (obj != null)
				return new RevDetails(Asn1Sequence.GetInstance(obj));

			return null;
        }

        private readonly CertTemplate m_certDetails;
		private readonly X509Extensions m_crlEntryDetails;

        private RevDetails(Asn1Sequence seq)
		{
			m_certDetails = CertTemplate.GetInstance(seq[0]);

            if (seq.Count > 1)
            {
                m_crlEntryDetails = X509Extensions.GetInstance(seq[1]);
            }
		}

		public RevDetails(CertTemplate certDetails)
            : this(certDetails, null)
		{
		}

        public RevDetails(CertTemplate certDetails, X509Extensions crlEntryDetails)
		{
            m_certDetails = certDetails;
            m_crlEntryDetails = crlEntryDetails;
		}

		public virtual CertTemplate CertDetails => m_certDetails;

        public virtual X509Extensions CrlEntryDetails => m_crlEntryDetails;

		/**
		* <pre>
		* RevDetails ::= SEQUENCE {
		*                  certDetails         CertTemplate,
		*                   -- allows requester to specify as much as they can about
		*                   -- the cert. for which revocation is requested
		*                   -- (e.g., for cases in which serialNumber is not available)
		*                   crlEntryDetails     Extensions       OPTIONAL
		*                   -- requested crlEntryExtensions
		*             }
		* </pre>
		* @return a basic ASN.1 object representation.
		*/
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(m_certDetails);
			v.AddOptional(m_crlEntryDetails);
			return new DerSequence(v);
		}
	}
}
