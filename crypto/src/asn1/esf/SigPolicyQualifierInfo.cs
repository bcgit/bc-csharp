using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// <code>
	/// SigPolicyQualifierInfo ::= SEQUENCE {
    ///		sigPolicyQualifierId  SigPolicyQualifierId,
	///		sigQualifier          ANY DEFINED BY sigPolicyQualifierId
	/// }
	/// 
	/// SigPolicyQualifierId ::= OBJECT IDENTIFIER
	/// </code>
	/// </remarks>
	public class SigPolicyQualifierInfo
		: Asn1Encodable
	{
        public static SigPolicyQualifierInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SigPolicyQualifierInfo sigPolicyQualifierInfo)
                return sigPolicyQualifierInfo;
            return new SigPolicyQualifierInfo(Asn1Sequence.GetInstance(obj));
        }

        public static SigPolicyQualifierInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SigPolicyQualifierInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SigPolicyQualifierInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SigPolicyQualifierInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_sigPolicyQualifierId;
        private readonly Asn1Encodable m_sigQualifier;

        private SigPolicyQualifierInfo(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count != 2)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_sigPolicyQualifierId = DerObjectIdentifier.GetInstance(seq[0]);
			m_sigQualifier = seq[1];
		}

        public SigPolicyQualifierInfo(DerObjectIdentifier sigPolicyQualifierId, Asn1Encodable sigQualifier)
        {
            m_sigPolicyQualifierId = sigPolicyQualifierId ?? throw new ArgumentNullException(nameof(sigPolicyQualifierId));
			m_sigQualifier = sigQualifier ?? throw new ArgumentNullException(nameof(sigQualifier));
		}

		public DerObjectIdentifier SigPolicyQualifierId => m_sigPolicyQualifierId;

        public Asn1Encodable SigQualifierData => m_sigQualifier;

		[Obsolete("Use 'SigQualifierData' instead")]
        public Asn1Object SigQualifier => m_sigQualifier.ToAsn1Object();

		public override Asn1Object ToAsn1Object() => new DerSequence(m_sigPolicyQualifierId, m_sigQualifier);
	}
}
