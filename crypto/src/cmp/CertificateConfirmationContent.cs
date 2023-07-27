using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Operators.Utilities;

namespace Org.BouncyCastle.Cmp
{
    public class CertificateConfirmationContent
    {
        public static CertificateConfirmationContent FromPkiBody(PkiBody pkiBody) =>
            FromPkiBody(pkiBody, DefaultDigestAlgorithmFinder.Instance);

        public static CertificateConfirmationContent FromPkiBody(PkiBody pkiBody,
            IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            if (!IsCertificateConfirmationContent(pkiBody.Type))
                throw new ArgumentException("content of PKIBody wrong type: " + pkiBody.Type);

            var content = CertConfirmContent.GetInstance(pkiBody.Content);

            return new CertificateConfirmationContent(content, digestAlgorithmFinder);
        }

        public static bool IsCertificateConfirmationContent(int bodyType) => PkiBody.TYPE_CERT_CONFIRM == bodyType;

        private readonly CertConfirmContent m_content;
        private readonly IDigestAlgorithmFinder m_digestAlgorithmFinder;

        public CertificateConfirmationContent(CertConfirmContent content)
            : this(content, DefaultDigestAlgorithmFinder.Instance)
        {
        }

        [Obsolete("Use constructor taking 'IDigestAlgorithmFinder' instead")]
        public CertificateConfirmationContent(CertConfirmContent content,
            Org.BouncyCastle.Cms.DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
            : this(content, (IDigestAlgorithmFinder)digestAlgFinder)
        {
        }

        public CertificateConfirmationContent(CertConfirmContent content, IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            m_content = content;
            m_digestAlgorithmFinder = digestAlgorithmFinder;
        }

        public CertConfirmContent ToAsn1Structure() => m_content;

        public CertificateStatus[] GetStatusMessages() => Array.ConvertAll(m_content.ToCertStatusArray(),
            element => new CertificateStatus(m_digestAlgorithmFinder, element));
    }
}
