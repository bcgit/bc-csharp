using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crmf
{
    public class CertificateRepMessage
    {
        public static CertificateRepMessage FromPkiBody(PkiBody pkiBody)
        {
            if (!IsCertificateRepMessage(pkiBody.Type))
                throw new ArgumentException("content of PKIBody wrong type: " + pkiBody.Type);

            return new CertificateRepMessage(CertRepMessage.GetInstance(pkiBody.Content));
        }

        public static bool IsCertificateRepMessage(int bodyType)
        {
            switch (bodyType)
            {
            case PkiBody.TYPE_INIT_REP:
            case PkiBody.TYPE_CERT_REP:
            case PkiBody.TYPE_KEY_UPDATE_REP:
            case PkiBody.TYPE_CROSS_CERT_REP:
                return true;
            default:
                return false;
            }
        }

        private readonly CertResponse[] m_resps;
        private readonly CmpCertificate[] m_caCerts;

        public CertificateRepMessage(CertRepMessage repMessage)
        {
            m_resps = repMessage.GetResponse();
            m_caCerts = repMessage.GetCAPubs();
        }

        public virtual CertificateResponse[] GetResponses() => Array.ConvertAll(m_resps, resp => new CertificateResponse(resp));

        public virtual X509Certificate[] GetX509Certificates()
        {
            List<X509Certificate> certs = new List<X509Certificate>();

            foreach (var caCert in m_caCerts)
            {
                if (caCert.IsX509v3PKCert)
                {
                    certs.Add(new X509Certificate(caCert.X509v3PKCert));
                }
            }

            return certs.ToArray();
        }

        /**
         * Return true if the message only contains X.509 public key certificates.
         *
         * @return true if only X.509 PK, false otherwise.
         */
        public virtual bool IsOnlyX509PKCertificates()
        {
            bool isOnlyX509 = true;

            foreach (var caCert in m_caCerts)
            {
                isOnlyX509 &= caCert.IsX509v3PKCert;
            }

            return isOnlyX509;
        }

        /**
         * Return the actual CMP certificates - useful if the array also contains non-X509 PK certificates.
         *
         * @return CMPCertificate array
         */
        public virtual CmpCertificate[] GetCmpCertificates() => (CmpCertificate[])m_caCerts.Clone();

        public virtual CertRepMessage ToAsn1Structure() => new CertRepMessage(m_caCerts, m_resps);
    }
}
