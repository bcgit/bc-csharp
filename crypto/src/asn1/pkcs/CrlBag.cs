using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class CrlBag
        : Asn1Encodable
    {
        public static CrlBag GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlBag crlBag)
                return crlBag;
            return new CrlBag(Asn1Sequence.GetInstance(obj));
        }

        public static CrlBag GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlBag(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CrlBag GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlBag(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_crlID;
        private readonly Asn1Encodable m_crlValue;

        private CrlBag(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_crlID = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_crlValue = Asn1Utilities.ReadContextTagged(seq, ref pos, 0, true,
                (taggedObject, declaredExplicit) => taggedObject.GetExplicitBaseObject());

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public CrlBag(DerObjectIdentifier crlID, Asn1Encodable crlValue)
        {
            m_crlID = crlID ?? throw new ArgumentNullException(nameof(crlID));
            m_crlValue = crlValue ?? throw new ArgumentNullException(nameof(crlValue));
        }

        public virtual DerObjectIdentifier CrlID => m_crlID;

        public virtual Asn1Encodable CrlValue => m_crlValue;

        public override Asn1Object ToAsn1Object() => new DerSequence(m_crlID, new DerTaggedObject(0, m_crlValue));
    }
}
