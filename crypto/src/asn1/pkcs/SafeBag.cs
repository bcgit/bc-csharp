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

        public static SafeBag GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new SafeBag(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerObjectIdentifier m_bagID;
        private readonly Asn1Object m_bagValue;
        private readonly Asn1Set m_bagAttributes;

        private SafeBag(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_bagID = DerObjectIdentifier.GetInstance(seq[pos++]);
            m_bagValue = Asn1TaggedObject.GetInstance(seq[pos++], Asn1Tags.ContextSpecific, 0)
                .GetExplicitBaseObject().ToAsn1Object();
            m_bagAttributes = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Set.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public SafeBag(DerObjectIdentifier oid, Asn1Object obj)
            : this(oid, obj, null)
        {
        }

        public SafeBag(DerObjectIdentifier oid, Asn1Object obj, Asn1Set bagAttributes)
        {
            m_bagID = oid ?? throw new ArgumentNullException(nameof(oid));
            m_bagValue = obj ?? throw new ArgumentNullException(nameof(obj));
            m_bagAttributes = bagAttributes;
        }

        public DerObjectIdentifier BagID => m_bagID;

        public Asn1Object BagValue => m_bagValue;

        public Asn1Set BagAttributes => m_bagAttributes;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_bagID, new DerTaggedObject(0, m_bagValue));
            v.AddOptional(m_bagAttributes);
            return new DerSequence(v);
        }
    }
}
