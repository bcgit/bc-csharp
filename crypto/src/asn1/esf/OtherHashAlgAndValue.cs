using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <summary>
    /// Summary description for OtherHashAlgAndValue.
    /// </summary>
    /// <remarks>
    /// <code>
    /// OtherHashAlgAndValue ::= SEQUENCE {
    ///		hashAlgorithm	AlgorithmIdentifier,
    /// 	hashValue		OtherHashValue
    /// }
    /// 
    /// OtherHashValue ::= OCTET STRING
    /// </code>
    /// </remarks>
    public class OtherHashAlgAndValue
		: Asn1Encodable
	{
        public static OtherHashAlgAndValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherHashAlgAndValue otherHashAlgAndValue)
                return otherHashAlgAndValue;
            return new OtherHashAlgAndValue(Asn1Sequence.GetInstance(obj));
        }

        public static OtherHashAlgAndValue GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherHashAlgAndValue(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static OtherHashAlgAndValue GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherHashAlgAndValue(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly Asn1OctetString m_hashValue;

        private OtherHashAlgAndValue(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count != 2)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_hashAlgorithm = AlgorithmIdentifier.GetInstance(seq[0]);
			m_hashValue = Asn1OctetString.GetInstance(seq[1]);
		}

		public OtherHashAlgAndValue(AlgorithmIdentifier	hashAlgorithm, byte[] hashValue)
		{
			m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
			m_hashValue = DerOctetString.FromContents(hashValue);
		}

        public OtherHashAlgAndValue(AlgorithmIdentifier hashAlgorithm, Asn1OctetString hashValue)
        {
			m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_hashValue = hashValue ?? throw new ArgumentNullException(nameof(hashValue));
		}

		public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

		public byte[] GetHashValue() => m_hashValue.GetOctets();

		public override Asn1Object ToAsn1Object() => new DerSequence(m_hashAlgorithm, m_hashValue);
	}
}
