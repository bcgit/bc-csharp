using System;
using System.Text;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>The result of a successful certification path validation.</summary>
    public class PkixCertPathValidatorResult
    {
        private readonly TrustAnchor m_trustAnchor;
        private readonly PkixPolicyNode m_policyTree;
        private readonly AsymmetricKeyParameter m_subjectPublicKey;

        /// <summary>Gets the root of the valid policy tree, or null if there is none.</summary>
        public PkixPolicyNode PolicyTree => m_policyTree;

        /// <summary>Gets the trust anchor that the path validated to.</summary>
        public TrustAnchor TrustAnchor => m_trustAnchor;

        /// <summary>Gets the public key of the end-entity certificate of the validated path.</summary>
        public AsymmetricKeyParameter SubjectPublicKey => m_subjectPublicKey;

        /// <summary>Create a result.</summary>
        /// <param name="trustAnchor">The trust anchor the path validated to.</param>
        /// <param name="policyTree">The valid policy tree, or null if none.</param>
        /// <param name="subjectPublicKey">The public key of the end-entity certificate.</param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="trustAnchor"/> or <paramref name="subjectPublicKey"/> is null.
        /// </exception>
        public PkixCertPathValidatorResult(TrustAnchor trustAnchor, PkixPolicyNode policyTree,
            AsymmetricKeyParameter subjectPublicKey)
        {
            m_trustAnchor = trustAnchor ?? throw new ArgumentNullException(nameof(trustAnchor));
            m_policyTree = policyTree;
            m_subjectPublicKey = subjectPublicKey ?? throw new ArgumentNullException(nameof(subjectPublicKey));
        }

        /// <summary>Return a copy of this result.</summary>
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
