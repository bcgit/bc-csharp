using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

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
		private readonly DerObjectIdentifier m_sigPolicyIdentifier;
		private readonly OtherHashAlgAndValue m_sigPolicyHash;
		private readonly Asn1Sequence m_sigPolicyQualifiers;

		public static SignaturePolicyId GetInstance(object obj)
		{
			if (obj == null)
				return null;

			if (obj is SignaturePolicyId signaturePolicyId)
				return signaturePolicyId;

			if (obj is Asn1Sequence asn1Sequence)
				return new SignaturePolicyId(asn1Sequence);

			throw new ArgumentException("Unknown object in 'SignaturePolicyId' factory: " + Platform.GetTypeName(obj),
				nameof(obj));
		}

		private SignaturePolicyId(Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException(nameof(seq));
			if (seq.Count < 2 || seq.Count > 3)
				throw new ArgumentException("Bad sequence size: " + seq.Count, nameof(seq));

			m_sigPolicyIdentifier = (DerObjectIdentifier)seq[0].ToAsn1Object();
			m_sigPolicyHash = OtherHashAlgAndValue.GetInstance(seq[1].ToAsn1Object());

			if (seq.Count > 2)
			{
				m_sigPolicyQualifiers = (Asn1Sequence)seq[2].ToAsn1Object();
			}
		}

		public SignaturePolicyId(DerObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash)
			: this(sigPolicyIdentifier, sigPolicyHash, null)
		{
		}

		public SignaturePolicyId(DerObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash,
			params SigPolicyQualifierInfo[]	sigPolicyQualifiers)
		{
			if (sigPolicyIdentifier == null)
				throw new ArgumentNullException(nameof(sigPolicyIdentifier));
			if (sigPolicyHash == null)
				throw new ArgumentNullException(nameof(sigPolicyHash));

			m_sigPolicyIdentifier = sigPolicyIdentifier;
			m_sigPolicyHash = sigPolicyHash;

			if (sigPolicyQualifiers != null)
			{
				m_sigPolicyQualifiers = new DerSequence(sigPolicyQualifiers);
			}
		}

		public SignaturePolicyId(DerObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash,
			IEnumerable<SigPolicyQualifierInfo> sigPolicyQualifiers)
		{
            if (sigPolicyIdentifier == null)
                throw new ArgumentNullException(nameof(sigPolicyIdentifier));
            if (sigPolicyHash == null)
                throw new ArgumentNullException(nameof(sigPolicyHash));

			m_sigPolicyIdentifier = sigPolicyIdentifier;
			m_sigPolicyHash = sigPolicyHash;

			if (sigPolicyQualifiers != null)
			{
				m_sigPolicyQualifiers = new DerSequence(Asn1EncodableVector.FromEnumerable(sigPolicyQualifiers));
			}
		}

		public DerObjectIdentifier SigPolicyIdentifier
		{
			get { return m_sigPolicyIdentifier; }
		}

		public OtherHashAlgAndValue SigPolicyHash
		{
			get { return m_sigPolicyHash; }
		}

		public SigPolicyQualifierInfo[] GetSigPolicyQualifiers()
		{
			return m_sigPolicyQualifiers?.MapElements(SigPolicyQualifierInfo.GetInstance);
		}

		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(
				m_sigPolicyIdentifier, m_sigPolicyHash.ToAsn1Object());

			if (m_sigPolicyQualifiers != null)
			{
				v.Add(m_sigPolicyQualifiers.ToAsn1Object());
			}

			return new DerSequence(v);
		}
	}
}
