using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Operators.Utilities;

namespace Org.BouncyCastle.Cmp
{
    /// <summary>The content of a CMP certificate confirmation message (CertConfirmContent, RFC 4210).</summary>
    public class CertificateConfirmationContent
    {
        /// <summary>Extract the certificate confirmation content from a PKIBody.</summary>
        /// <param name="pkiBody">The PKIBody; its type must be a certificate confirmation.</param>
        /// <returns>The content.</returns>
        /// <exception cref="ArgumentException">The body is not of the certificate confirmation type.</exception>
        public static CertificateConfirmationContent FromPkiBody(PkiBody pkiBody) =>
            FromPkiBody(pkiBody, DefaultDigestAlgorithmFinder.Instance);

        /// <summary>Extract the certificate confirmation content from a PKIBody.</summary>
        /// <param name="pkiBody">The PKIBody; its type must be a certificate confirmation.</param>
        /// <param name="digestAlgorithmFinder">Finds the digest algorithm matching a signature algorithm.</param>
        /// <returns>The content.</returns>
        /// <exception cref="ArgumentException">The body is not of the certificate confirmation type.</exception>
        public static CertificateConfirmationContent FromPkiBody(PkiBody pkiBody,
            IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            if (!IsCertificateConfirmationContent(pkiBody.Type))
                throw new ArgumentException("content of PKIBody wrong type: " + pkiBody.Type);

            var content = CertConfirmContent.GetInstance(pkiBody.Content);

            return new CertificateConfirmationContent(content, digestAlgorithmFinder);
        }

        /// <summary>Return whether the given PKIBody type is the certificate confirmation type.</summary>
        /// <param name="bodyType">The PKIBody type.</param>
        public static bool IsCertificateConfirmationContent(int bodyType) => PkiBody.TYPE_CERT_CONFIRM == bodyType;

        private readonly CertConfirmContent m_content;
        private readonly IDigestAlgorithmFinder m_digestAlgorithmFinder;

        /// <summary>Wrap a CertConfirmContent, using the default digest algorithm finder.</summary>
        /// <param name="content">The ASN.1 structure.</param>
        public CertificateConfirmationContent(CertConfirmContent content)
            : this(content, DefaultDigestAlgorithmFinder.Instance)
        {
        }

        /// <summary>Create a new <see cref="CertificateConfirmationContent"/>.</summary>
        /// <param name="content">The content.</param>
        /// <param name="digestAlgFinder">The digest alg finder.</param>
        [Obsolete("Use constructor taking 'IDigestAlgorithmFinder' instead")]
        public CertificateConfirmationContent(CertConfirmContent content,
            Cms.DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
            : this(content, (IDigestAlgorithmFinder)digestAlgFinder)
        {
        }

        /// <summary>Wrap a CertConfirmContent.</summary>
        /// <param name="content">The ASN.1 structure.</param>
        /// <param name="digestAlgorithmFinder">Finds the digest algorithm matching a signature algorithm.</param>
        public CertificateConfirmationContent(CertConfirmContent content, IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            m_content = content;
            m_digestAlgorithmFinder = digestAlgorithmFinder;
        }

        /// <summary>Return the underlying ASN.1 structure.</summary>
        public CertConfirmContent ToAsn1Structure() => m_content;

        /// <summary>Return the status of each certificate being confirmed.</summary>
        public CertificateStatus[] GetStatusMessages() => Array.ConvertAll(m_content.ToCertStatusArray(),
            element => new CertificateStatus(m_digestAlgorithmFinder, element));
    }
}
