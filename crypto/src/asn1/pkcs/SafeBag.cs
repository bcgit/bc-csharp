using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class SafeBag
        : Asn1Encodable
    {
        public static SafeBag GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SafeBag safeBag)
                return safeBag;
            return new SafeBag(Asn1Sequence.GetInstance(obj));
        }

        public static SafeBag GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SafeBag(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SafeBag GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SafeBag(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_bagID;
        private readonly Asn1Encodable m_bagValue;
        private readonly Asn1Set m_bagAttributes;

        private SafeBag(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_bagID = DerObjectIdentifier.GetInstance(seq[pos++]);
            m_bagValue = Asn1TaggedObject.GetInstance(seq[pos++], Asn1Tags.ContextSpecific, 0).GetExplicitBaseObject();
            m_bagAttributes = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Set.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        // TODO[api] Remove as redundant
        public SafeBag(DerObjectIdentifier oid, Asn1Object obj)
            : this(oid, obj, null)
        {
        }

        // TODO[api] Remove as redundant
        public SafeBag(DerObjectIdentifier oid, Asn1Object obj, Asn1Set bagAttributes)
        {
            m_bagID = oid ?? throw new ArgumentNullException(nameof(oid));
            m_bagValue = obj ?? throw new ArgumentNullException(nameof(obj));
            m_bagAttributes = bagAttributes;
        }

        public SafeBag(DerObjectIdentifier bagID, Asn1Encodable bagValue)
            : this(bagID, bagValue, null)
        {
        }

        public SafeBag(DerObjectIdentifier bagID, Asn1Encodable bagValue, Asn1Set bagAttributes)
        {
            m_bagID = bagID ?? throw new ArgumentNullException(nameof(bagID));
            m_bagValue = bagValue ?? throw new ArgumentNullException(nameof(bagValue));
            m_bagAttributes = bagAttributes;
        }

        public DerObjectIdentifier BagID => m_bagID;

        // TODO[api] Return Asn1Encodable (and obsolete BagValueEncodable)
        public Asn1Object BagValue => m_bagValue.ToAsn1Object();

        public Asn1Encodable BagValueEncodable => m_bagValue;

        public Asn1Set BagAttributes => m_bagAttributes;

        public override Asn1Object ToAsn1Object()
        {
            var taggedBagValue = new DerTaggedObject(isExplicit: true, 0, m_bagValue);

            return m_bagAttributes == null
                ?   new DerSequence(m_bagID, taggedBagValue)
                :   new DerSequence(m_bagID, taggedBagValue, m_bagAttributes);
        }
    }
}
