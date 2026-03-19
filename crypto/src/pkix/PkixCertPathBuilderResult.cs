using System;
using System.Text;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkix
{
    public class PkixCertPathBuilderResult
        : PkixCertPathValidatorResult
    {
        private readonly PkixCertPath m_certPath;

        public PkixCertPathBuilderResult(PkixCertPath certPath, TrustAnchor trustAnchor, PkixPolicyNode policyTree,
            AsymmetricKeyParameter subjectPublicKey)
            : base(trustAnchor, policyTree, subjectPublicKey)
        {
            m_certPath = certPath ?? throw new ArgumentNullException(nameof(certPath));
        }

        public PkixCertPath CertPath => m_certPath;

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("SimplePKIXCertPathBuilderResult: [");
            sb.Append("  Certification Path: ").Append(CertPath).AppendLine();
            sb.Append("  Trust Anchor: ").Append(TrustAnchor.TrustedCert.IssuerDN).AppendLine();
            sb.Append("  Subject Public Key: ").Append(SubjectPublicKey).AppendLine();
            return sb.ToString();
        }
    }
}
