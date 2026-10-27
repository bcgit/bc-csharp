using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>A set of certificate requests (CertReqMessages, RFC 4211) carried in a CMP message.</summary>
    public class CertificateReqMessages
    {
        /// <summary>Extract the request messages from a PKIBody.</summary>
        /// <param name="pkiBody">The PKIBody; its type must be one of the certificate request types.</param>
        /// <exception cref="ArgumentException">The body is not of a certificate request type.</exception>
        public static CertificateReqMessages FromPkiBody(PkiBody pkiBody)
        {
            if (!IsCertificateRequestMessages(pkiBody.Type))
                throw new ArgumentException("content of PKIBody wrong type: " + pkiBody.Type);

            return new CertificateReqMessages(CertReqMessages.GetInstance(pkiBody.Content));
        }

        /// <summary>Return whether the given PKIBody type carries certificate request messages.</summary>
        /// <param name="bodyType">The PKIBody type.</param>
        public static bool IsCertificateRequestMessages(int bodyType)
        {
            switch (bodyType)
            {
            case PkiBody.TYPE_INIT_REQ:
            case PkiBody.TYPE_CERT_REQ:
            case PkiBody.TYPE_KEY_UPDATE_REQ:
            case PkiBody.TYPE_KEY_RECOVERY_REQ:
            case PkiBody.TYPE_CROSS_CERT_REQ:
                return true;
            default:
                return false;
            }
        }

        private readonly CertReqMsg[] m_reqs;

        /// <summary>Wrap a CertReqMessages structure.</summary>
        /// <param name="certReqMessages">The ASN.1 structure.</param>
        public CertificateReqMessages(CertReqMessages certReqMessages)
        {
            m_reqs = certReqMessages.ToCertReqMsgArray();
        }

        /// <summary>Return the individual request messages.</summary>
        public virtual CertificateRequestMessage[] GetRequests() =>
            Array.ConvertAll(m_reqs, req => new CertificateRequestMessage(req));

        /// <summary>Return the underlying ASN.1 structure.</summary>
        public virtual CertReqMessages ToAsn1Structure() => new CertReqMessages(m_reqs);
    }
}
