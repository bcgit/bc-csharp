using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class CertBag
        : Asn1Encodable
    {
        public static CertBag GetInstance(object obj)
        {
            if (obj is CertBag certBag)
                return certBag;
            if (obj == null)
                return null;
            return new CertBag(Asn1Sequence.GetInstance(obj));
        }

        private readonly DerObjectIdentifier m_certID;
        private readonly Asn1Object m_certValue;

		private CertBag(Asn1Sequence seq)
        {
			if (seq.Count != 2)
				throw new ArgumentException("Wrong number of elements in sequence", nameof(seq));

            this.m_certID = DerObjectIdentifier.GetInstance(seq[0]);
            this.m_certValue = Asn1TaggedObject.GetInstance(seq[1]).GetExplicitBaseObject().ToAsn1Object();
        }

		public CertBag(DerObjectIdentifier certID, Asn1Object certValue)
        {
            m_certID = certID;
            m_certValue = certValue;
        }

        public virtual DerObjectIdentifier CertID => m_certID;

        public virtual Asn1Object CertValue => m_certValue;

		public override Asn1Object ToAsn1Object()
        {
			return new DerSequence(m_certID, new DerTaggedObject(0, m_certValue));
        }
    }
}
