using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Cms;

namespace Org.BouncyCastle.Cmp
{
    public class CertificateConfirmationContent
    {
        public static CertificateConfirmationContent FromPkiBody(PkiBody pkiBody) =>
            FromPkiBody(pkiBody, DefaultDigestAlgorithmIdentifierFinder.Instance);

        public static CertificateConfirmationContent FromPkiBody(PkiBody pkiBody,
            DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
        {
            if (!IsCertificateConfirmationContent(pkiBody.Type))
                throw new ArgumentException("content of PkiBody wrong type: " + pkiBody.Type);

            return new CertificateConfirmationContent(CertConfirmContent.GetInstance(pkiBody.Content), digestAlgFinder);
        }

        public static bool IsCertificateConfirmationContent(int bodyType) => PkiBody.TYPE_CERT_CONFIRM == bodyType;

        private readonly CertConfirmContent m_content;
        private readonly DefaultDigestAlgorithmIdentifierFinder m_digestAlgIDFinder;

        public CertificateConfirmationContent(CertConfirmContent content)
            : this(content, DefaultDigestAlgorithmIdentifierFinder.Instance)
        {
        }

        public CertificateConfirmationContent(CertConfirmContent content,
            DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
        {
            m_content = content;
            m_digestAlgIDFinder = digestAlgFinder;
        }

        public CertConfirmContent ToAsn1Structure() => m_content;

        public CertificateStatus[] GetStatusMessages() => Array.ConvertAll(m_content.ToCertStatusArray(),
            element => new CertificateStatus(m_digestAlgIDFinder, element));
    }
}
