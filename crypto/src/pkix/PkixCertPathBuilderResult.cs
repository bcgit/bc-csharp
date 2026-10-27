using System;
using System.Text;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>The result of a successful certification path build, including the path that was found.</summary>
    public class PkixCertPathBuilderResult
        : PkixCertPathValidatorResult
    {
        private readonly PkixCertPath m_certPath;

        /// <summary>Create a result.</summary>
        /// <param name="certPath">The validated certification path.</param>
        /// <param name="trustAnchor">The trust anchor the path validated to.</param>
        /// <param name="policyTree">The valid policy tree, or null if none.</param>
        /// <param name="subjectPublicKey">The public key of the end-entity certificate.</param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="certPath"/>, <paramref name="trustAnchor"/> or <paramref name="subjectPublicKey"/> is null.
        /// </exception>
        public PkixCertPathBuilderResult(PkixCertPath certPath, TrustAnchor trustAnchor, PkixPolicyNode policyTree,
            AsymmetricKeyParameter subjectPublicKey)
            : base(trustAnchor, policyTree, subjectPublicKey)
        {
            m_certPath = certPath ?? throw new ArgumentNullException(nameof(certPath));
        }

        /// <summary>Gets the validated certification path.</summary>
        public PkixCertPath CertPath => m_certPath;

        /// <inheritdoc/>
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
