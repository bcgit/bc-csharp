using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// <code>
	/// OtherCertID ::= SEQUENCE {
	/// 	otherCertHash	OtherHash,
	/// 	issuerSerial	IssuerSerial OPTIONAL
	/// }
	/// </code>
	/// </remarks>
	public class OtherCertID
		: Asn1Encodable
	{
        public static OtherCertID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherCertID otherCertID)
                return otherCertID;
            return new OtherCertID(Asn1Sequence.GetInstance(obj));
		}

        public static OtherCertID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
			new OtherCertID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static OtherCertID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherCertID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly OtherHash m_otherCertHash;
        private readonly IssuerSerial m_issuerSerial;

        private OtherCertID(Asn1Sequence seq)
		{
			int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_otherCertHash = OtherHash.GetInstance(seq[0]);

			if (count > 1)
			{
				m_issuerSerial = IssuerSerial.GetInstance(seq[1]);
			}
		}

        public OtherCertID(OtherHash otherCertHash)
            : this(otherCertHash, null)
        {
        }

        public OtherCertID(OtherHash otherCertHash, IssuerSerial issuerSerial)
        {
            m_otherCertHash = otherCertHash ?? throw new ArgumentNullException(nameof(otherCertHash));
			m_issuerSerial = issuerSerial;
		}

		public OtherHash OtherCertHash => m_otherCertHash;

		public IssuerSerial IssuerSerial => m_issuerSerial;

		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(2);
			v.Add(m_otherCertHash);
			v.AddOptional(m_issuerSerial);
			return new DerSequence(v);
		}
	}
}
