using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// <code>
	/// SignaturePolicyIdentifier ::= CHOICE {
	///		SignaturePolicyId		SignaturePolicyId,
	///		SignaturePolicyImplied	SignaturePolicyImplied
	/// }
	/// 
	/// SignaturePolicyImplied ::= NULL
	/// </code>
	/// </remarks>
	public class SignaturePolicyIdentifier
		: Asn1Encodable, IAsn1Choice
	{
		public static SignaturePolicyIdentifier GetInstance(object obj)
		{
			if (obj == null)
				return null;

			if (obj is SignaturePolicyIdentifier signaturePolicyIdentifier)
				return signaturePolicyIdentifier;

            if (obj is Asn1Null)
                return new SignaturePolicyIdentifier();

			return new SignaturePolicyIdentifier(SignaturePolicyId.GetInstance(obj));
		}

        public static SignaturePolicyIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return Asn1Utilities.GetInstanceFromChoice(taggedObject, declaredExplicit, GetInstance);
        }

        private readonly SignaturePolicyId m_sigPolicy;

        public SignaturePolicyIdentifier()
		{
			m_sigPolicy = null;
		}

		public SignaturePolicyIdentifier(SignaturePolicyId signaturePolicyId)
		{
			m_sigPolicy = signaturePolicyId ?? throw new ArgumentNullException(nameof(signaturePolicyId));
        }

        public SignaturePolicyId SignaturePolicyId => m_sigPolicy;

		public override Asn1Object ToAsn1Object() => m_sigPolicy?.ToAsn1Object() ?? DerNull.Instance;
	}
}
