using System;

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
            if (obj == null)
                return null;
            if (obj is RevDetails revDetails)
                return revDetails;
            return new RevDetails(Asn1Sequence.GetInstance(obj));
        }

        public static RevDetails GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new RevDetails(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly CertTemplate m_certDetails;
		private readonly X509Extensions m_crlEntryDetails;

        private RevDetails(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certDetails = CertTemplate.GetInstance(seq[pos++]);
            m_crlEntryDetails = Asn1Utilities.ReadOptional(seq, ref pos, X509Extensions.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

		public RevDetails(CertTemplate certDetails)
            : this(certDetails, null)
		{
		}

        public RevDetails(CertTemplate certDetails, X509Extensions crlEntryDetails)
		{
            m_certDetails = certDetails ?? throw new ArgumentNullException(nameof(certDetails));
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
            return m_crlEntryDetails == null
                ?  new DerSequence(m_certDetails)
                :  new DerSequence(m_certDetails, m_crlEntryDetails);
		}
	}
}
