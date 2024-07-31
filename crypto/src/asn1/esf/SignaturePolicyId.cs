using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// <code>
    /// SignaturePolicyId ::= SEQUENCE {
    /// 	sigPolicyIdentifier		SigPolicyId,
    /// 	sigPolicyHash			SigPolicyHash,
    /// 	sigPolicyQualifiers		SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo OPTIONAL
    /// }
    /// 
    /// SigPolicyId ::= OBJECT IDENTIFIER
    /// 
    /// SigPolicyHash ::= OtherHashAlgAndValue
    /// </code>
    /// </remarks>
    public class SignaturePolicyId
		: Asn1Encodable
	{
		public static SignaturePolicyId GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is SignaturePolicyId signaturePolicyId)
				return signaturePolicyId;
			return new SignaturePolicyId(Asn1Sequence.GetInstance(obj));
		}

        public static SignaturePolicyId GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignaturePolicyId(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SignaturePolicyId GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignaturePolicyId(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_sigPolicyIdentifier;
        private readonly OtherHashAlgAndValue m_sigPolicyHash;
        private readonly Asn1Sequence m_sigPolicyQualifiers;

        private SignaturePolicyId(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count < 2 || count > 3)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_sigPolicyIdentifier = DerObjectIdentifier.GetInstance(seq[0]);
			m_sigPolicyHash = OtherHashAlgAndValue.GetInstance(seq[1]);

			if (count > 2)
			{
				m_sigPolicyQualifiers = Asn1Sequence.GetInstance(seq[2]);
			}
		}

		public SignaturePolicyId(DerObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash)
			: this(sigPolicyIdentifier, sigPolicyHash, null)
		{
		}

		public SignaturePolicyId(DerObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash,
			params SigPolicyQualifierInfo[]	sigPolicyQualifiers)
		{
			m_sigPolicyIdentifier = sigPolicyIdentifier ?? throw new ArgumentNullException(nameof(sigPolicyIdentifier));
            m_sigPolicyHash = sigPolicyHash ?? throw new ArgumentNullException(nameof(sigPolicyHash));
            m_sigPolicyQualifiers = DerSequence.FromElementsOptional(sigPolicyQualifiers);
		}

		public SignaturePolicyId(DerObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash,
			IEnumerable<SigPolicyQualifierInfo> sigPolicyQualifiers)
		{
			m_sigPolicyIdentifier = sigPolicyIdentifier ?? throw new ArgumentNullException(nameof(sigPolicyIdentifier));
            m_sigPolicyHash = sigPolicyHash ?? throw new ArgumentNullException(nameof(sigPolicyHash));

            if (sigPolicyQualifiers != null)
			{
				m_sigPolicyQualifiers = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(sigPolicyQualifiers));
			}
		}

		public DerObjectIdentifier SigPolicyIdentifier => m_sigPolicyIdentifier;

		public OtherHashAlgAndValue SigPolicyHash => m_sigPolicyHash;

		public SigPolicyQualifierInfo[] GetSigPolicyQualifiers() =>
			m_sigPolicyQualifiers?.MapElements(SigPolicyQualifierInfo.GetInstance);

		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
			v.Add(m_sigPolicyIdentifier, m_sigPolicyHash);
			v.AddOptional(m_sigPolicyQualifiers);
			return new DerSequence(v);
		}
	}
}
