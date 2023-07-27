using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Crmf
{
    public class CertificateReqMessages
    {
        public static CertificateReqMessages FromPkiBody(PkiBody pkiBody)
        {
            if (!IsCertificateRequestMessages(pkiBody.Type))
                throw new ArgumentException("content of PKIBody wrong type: " + pkiBody.Type);

            return new CertificateReqMessages(CertReqMessages.GetInstance(pkiBody.Content));
        }

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

        public CertificateReqMessages(CertReqMessages certReqMessages)
        {
            m_reqs = certReqMessages.ToCertReqMsgArray();
        }

        public virtual CertificateRequestMessage[] GetRequests() =>
            Array.ConvertAll(m_reqs, req => new CertificateRequestMessage(req));

        public virtual CertReqMessages ToAsn1Structure() => new CertReqMessages(m_reqs);
    }
}
