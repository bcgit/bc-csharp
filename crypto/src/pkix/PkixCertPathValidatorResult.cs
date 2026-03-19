using System;
using System.Text;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkix
{
    public class PkixCertPathValidatorResult
    {
        private readonly TrustAnchor m_trustAnchor;
        private readonly PkixPolicyNode m_policyTree;
        private readonly AsymmetricKeyParameter m_subjectPublicKey;

        public PkixPolicyNode PolicyTree => m_policyTree;

        public TrustAnchor TrustAnchor => m_trustAnchor;

        public AsymmetricKeyParameter SubjectPublicKey => m_subjectPublicKey;

        public PkixCertPathValidatorResult(TrustAnchor trustAnchor, PkixPolicyNode policyTree,
            AsymmetricKeyParameter subjectPublicKey)
        {
            m_trustAnchor = trustAnchor ?? throw new ArgumentNullException(nameof(trustAnchor));
            m_policyTree = policyTree;
            m_subjectPublicKey = subjectPublicKey ?? throw new ArgumentNullException(nameof(subjectPublicKey));
        }

        public object Clone() => new PkixCertPathValidatorResult(TrustAnchor, PolicyTree, SubjectPublicKey);

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("PKIXCertPathValidatorResult: [");
            sb.Append("  Trust Anchor: ").Append(TrustAnchor).AppendLine();
            sb.Append("  Policy Tree: ").Append(PolicyTree).AppendLine();
            sb.Append("  Subject Public Key: ").Append(SubjectPublicKey).AppendLine();
            return sb.ToString();
        }
    }
}
