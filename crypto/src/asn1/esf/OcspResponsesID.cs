using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// OcspResponsesID ::= SEQUENCE {
    ///		ocspIdentifier	OcspIdentifier,
    ///		ocspRepHash		OtherHash OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class OcspResponsesID
		: Asn1Encodable
	{
        public static OcspResponsesID GetInstance(object obj)
        {
			if (obj == null)
				return null;
            if (obj is OcspResponsesID ocspResponsesID)
                return ocspResponsesID;
            return new OcspResponsesID(Asn1Sequence.GetInstance(obj));
        }

        public static OcspResponsesID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspResponsesID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static OcspResponsesID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspResponsesID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly OcspIdentifier m_ocspIdentifier;
        private readonly OtherHash m_ocspRepHash;

        private OcspResponsesID(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count < 1 || count > 2)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_ocspIdentifier = OcspIdentifier.GetInstance(seq[0]);

			if (seq.Count > 1)
			{
				m_ocspRepHash = OtherHash.GetInstance(seq[1]);
			}
		}

        public OcspResponsesID(OcspIdentifier ocspIdentifier)
            : this(ocspIdentifier, null)
        {
        }

        public OcspResponsesID(OcspIdentifier ocspIdentifier, OtherHash ocspRepHash)
        {
			m_ocspIdentifier = ocspIdentifier ?? throw new ArgumentNullException(nameof(ocspIdentifier));
            m_ocspRepHash = ocspRepHash;
		}

		public OcspIdentifier OcspIdentifier => m_ocspIdentifier;

		public OtherHash OcspRepHash => m_ocspRepHash;

		public override Asn1Object ToAsn1Object()
		{
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_ocspIdentifier);
            v.AddOptional(m_ocspRepHash);
			return new DerSequence(v);
		}
	}
}
