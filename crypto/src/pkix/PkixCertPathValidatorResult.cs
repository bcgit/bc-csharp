using System;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pkix
{
	/// <summary>
	/// Summary description for PkixCertPathValidatorResult.
	/// </summary>
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

		public PkixCertPathValidatorResult(
			TrustAnchor				trustAnchor,
			PkixPolicyNode			policyTree,
			AsymmetricKeyParameter	subjectPublicKey)
		{
			if (subjectPublicKey == null)
			{
				throw new NullReferenceException("subjectPublicKey must be non-null");
			}
			if (trustAnchor == null)
			{
				throw new NullReferenceException("trustAnchor must be non-null");
			}
			
			this.trustAnchor = trustAnchor;
			this.policyTree = policyTree;
			this.subjectPublicKey = subjectPublicKey;
		}

		public object Clone()
		{
			return new PkixCertPathValidatorResult(this.TrustAnchor, this.PolicyTree, this.SubjectPublicKey);
		}

		public override string ToString() 
		{
			StringBuilder sb = new StringBuilder();
			sb.AppendLine("PKIXCertPathValidatorResult: [");
			sb.Append("  Trust Anchor: ").AppendLine(TrustAnchor.ToString());
			sb.Append("  Policy Tree: ").AppendLine(PolicyTree.ToString());
			sb.Append("  Subject Public Key: ").AppendLine(SubjectPublicKey.ToString());
			return sb.ToString();
		}
	}
}
