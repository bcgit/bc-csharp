using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>A certificate response message (CertRepMessage, RFC 4210) carried in a CMP message.</summary>
    public class CertificateRepMessage
    {
        /// <summary>Extract the response message from a PKIBody.</summary>
        /// <param name="pkiBody">The PKIBody; its type must be one of the certificate response types.</param>
        /// <exception cref="ArgumentException">The body is not of a certificate response type.</exception>
        public static CertificateRepMessage FromPkiBody(PkiBody pkiBody)
        {
            if (!IsCertificateRepMessage(pkiBody.Type))
                throw new ArgumentException("content of PKIBody wrong type: " + pkiBody.Type);

            return new CertificateRepMessage(CertRepMessage.GetInstance(pkiBody.Content));
        }

        /// <summary>Return whether the given PKIBody type carries a certificate response message.</summary>
        /// <param name="bodyType">The PKIBody type.</param>
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

        /// <summary>Wrap a CertRepMessage structure.</summary>
        /// <param name="repMessage">The ASN.1 structure.</param>
        public CertificateRepMessage(CertRepMessage repMessage)
        {
            m_resps = repMessage.GetResponse();
            m_caCerts = repMessage.GetCAPubs();
        }

        /// <summary>Return the individual certificate responses.</summary>
        public virtual CertificateResponse[] GetResponses() => Array.ConvertAll(m_resps, resp => new CertificateResponse(resp));

        /// <summary>Return the X.509 certificates among the CA certificates in the message.</summary>
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

        /// <summary>Return true if the message only contains X.509 public key certificates.</summary>
        /// <returns>true if only X.509 PK, false otherwise.</returns>
        public virtual bool IsOnlyX509PKCertificates()
        {
            bool isOnlyX509 = true;

            foreach (var caCert in m_caCerts)
            {
                isOnlyX509 &= caCert.IsX509v3PKCert;
            }

            return isOnlyX509;
        }

        /// <summary>
        /// Return the actual CMP certificates - useful if the array also contains non-X509 PK certificates.
        /// </summary>
        /// <returns>A copy of the array of CMP certificates.</returns>
        public virtual CmpCertificate[] GetCmpCertificates() => (CmpCertificate[])m_caCerts.Clone();

        /// <summary>Return the underlying ASN.1 structure.</summary>
        public virtual CertRepMessage ToAsn1Structure() => new CertRepMessage(m_caCerts, m_resps);
    }
}
