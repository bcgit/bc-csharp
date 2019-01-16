
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Asn1.Cmp;


namespace Org.BouncyCastle.Cmp
{
    public class CertificateConfirmationContent
    {
        private DefaultDigestAlgorithmIdentifierFinder digestAlgFinder;
        private CertConfirmContent content;


        public CertificateConfirmationContent(CertConfirmContent content)
        {
            this.content = content;
        }

        public CertificateConfirmationContent(CertConfirmContent content,
            DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
        {
            this.content = content;
            this.digestAlgFinder = digestAlgFinder;
        }

        public CertConfirmContent ToAsn1Structure()
        {
            return content;
        }

        public CertificateStatus[] GetStatusMessages()
        {
            CertStatus[] statusArray = content.ToCertStatusArray();
            CertificateStatus[] ret = new CertificateStatus[statusArray.Length];
            for (int i = 0; i != ret.Length; i++)
            {
                ret[i] = new CertificateStatus(digestAlgFinder, statusArray[i]);
            }

            return ret;
        } 
    }
}
