using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Cms;

namespace Org.BouncyCastle.Cmp
{
    public class CertificateConfirmationContent
    {
        private readonly DefaultDigestAlgorithmIdentifierFinder m_digestAlgFinder;
        private readonly CertConfirmContent m_content;

        public CertificateConfirmationContent(CertConfirmContent content)
        {
            this.m_content = content;
        }

        public CertificateConfirmationContent(CertConfirmContent content,
            DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
        {
            this.m_content = content;
            this.m_digestAlgFinder = digestAlgFinder;
        }

        public CertConfirmContent ToAsn1Structure()
        {
            return m_content;
        }

        public CertificateStatus[] GetStatusMessages()
        {
            CertStatus[] statusArray = m_content.ToCertStatusArray();
            CertificateStatus[] ret = new CertificateStatus[statusArray.Length];
            for (int i = 0; i != ret.Length; i++)
            {
                ret[i] = new CertificateStatus(m_digestAlgFinder, statusArray[i]);
            }

            return ret;
        }
    }
}
