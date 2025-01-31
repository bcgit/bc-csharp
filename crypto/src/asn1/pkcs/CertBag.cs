using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class CertBag
        : Asn1Encodable
    {
        public static CertBag GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertBag certBag)
                return certBag;
            return new CertBag(Asn1Sequence.GetInstance(obj));
        }

        public static CertBag GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertBag(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertBag GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertBag(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_certID;
        private readonly Asn1Object m_certValue;

		private CertBag(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certID = DerObjectIdentifier.GetInstance(seq[0]);
            m_certValue = Asn1TaggedObject.GetInstance(seq[1], Asn1Tags.ContextSpecific, 0)
                .GetExplicitBaseObject().ToAsn1Object();
        }

		public CertBag(DerObjectIdentifier certID, Asn1Object certValue)
        {
            m_certID = certID ?? throw new ArgumentNullException(nameof(certID));
            m_certValue = certValue ?? throw new ArgumentNullException(nameof(certValue));
        }

        public virtual DerObjectIdentifier CertID => m_certID;

        // TODO[api] Prefer returning IAsn1Convertible
        public virtual Asn1Object CertValue => m_certValue;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_certID, new DerTaggedObject(0, m_certValue));
    }
}
