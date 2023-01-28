using System;
using System.Text;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkix
{
	public class PkixCertPathValidatorResult
		//: ICertPathValidatorResult
	{
		private TrustAnchor trustAnchor;
		private PkixPolicyNode policyTree;
		private AsymmetricKeyParameter subjectPublicKey;

		public PkixPolicyNode PolicyTree
		{
			get { return this.policyTree; }
		}

		public TrustAnchor TrustAnchor
		{
			get { return this.trustAnchor; }
		}

		public AsymmetricKeyParameter SubjectPublicKey
		{
			get { return this.subjectPublicKey; }
		}

		public PkixCertPathValidatorResult(TrustAnchor trustAnchor, PkixPolicyNode policyTree,
			AsymmetricKeyParameter subjectPublicKey)
		{
			this.trustAnchor = trustAnchor ?? throw new ArgumentNullException(nameof(trustAnchor));
            this.policyTree = policyTree;
			this.subjectPublicKey = subjectPublicKey ?? throw new ArgumentNullException(nameof(subjectPublicKey));
        }

		public object Clone()
		{
			return new PkixCertPathValidatorResult(this.TrustAnchor, this.PolicyTree, this.SubjectPublicKey);
		}

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
