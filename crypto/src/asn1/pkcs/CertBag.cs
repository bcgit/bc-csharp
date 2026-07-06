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
        private readonly Asn1Encodable m_certValue;

		private CertBag(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certID = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_certValue = Asn1Utilities.ReadContextTagged(seq, ref pos, 0, true,
                (taggedObject, declaredExplicit) => taggedObject.GetExplicitBaseObject());

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        // TODO[api] Remove as redundant
        public CertBag(DerObjectIdentifier certID, Asn1Object certValue)
        {
            m_certID = certID ?? throw new ArgumentNullException(nameof(certID));
            m_certValue = certValue ?? throw new ArgumentNullException(nameof(certValue));
        }

        public CertBag(DerObjectIdentifier certID, Asn1Encodable certValue)
        {
            m_certID = certID ?? throw new ArgumentNullException(nameof(certID));
            m_certValue = certValue ?? throw new ArgumentNullException(nameof(certValue));
        }

        public virtual DerObjectIdentifier CertID => m_certID;

        // TODO[api] Return Asn1Encodable (and obsolete CertValueEncodable)
        public virtual Asn1Object CertValue => m_certValue.ToAsn1Object();

        public virtual Asn1Encodable CertValueEncodable => m_certValue;

        public override Asn1Object ToAsn1Object() => new DerSequence(m_certID, new DerTaggedObject(0, m_certValue));
    }
}
