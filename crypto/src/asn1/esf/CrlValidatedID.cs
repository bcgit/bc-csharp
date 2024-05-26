using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// CrlValidatedID ::= SEQUENCE {
    ///		crlHash			OtherHash,
    ///		crlIdentifier	CrlIdentifier OPTIONAL}
    /// </code>
    /// </remarks>
    public class CrlValidatedID
		: Asn1Encodable
	{
        public static CrlValidatedID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlValidatedID crlValidatedID)
                return crlValidatedID;
            return new CrlValidatedID(Asn1Sequence.GetInstance(obj));
        }

        public static CrlValidatedID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CrlValidatedID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly OtherHash m_crlHash;
        private readonly CrlIdentifier m_crlIdentifier;

        private CrlValidatedID(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count < 1 || count > 2)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_crlHash = OtherHash.GetInstance(seq[0]);

			if (count > 1)
			{
				m_crlIdentifier = CrlIdentifier.GetInstance(seq[1]);
			}
		}

		public CrlValidatedID(OtherHash crlHash)
			: this(crlHash, null)
		{
		}

        public CrlValidatedID(OtherHash crlHash, CrlIdentifier crlIdentifier)
        {
			m_crlHash = crlHash ?? throw new ArgumentNullException(nameof(crlHash));
            m_crlIdentifier = crlIdentifier;
		}

		public OtherHash CrlHash => m_crlHash;

		public CrlIdentifier CrlIdentifier => m_crlIdentifier;

		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(2);
			v.Add(m_crlHash);
			v.AddOptional(m_crlIdentifier);
			return new DerSequence(v);
		}
	}
}
