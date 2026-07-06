using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /**
     * the infamous Pfx from Pkcs12
     */
    public class Pfx
        : Asn1Encodable
    {
        public static Pfx GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Pfx pfx)
                return pfx;
            return new Pfx(Asn1Sequence.GetInstance(obj));
        }

        public static Pfx GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Pfx(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Pfx GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Pfx(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly ContentInfo m_contentInfo;
        private readonly MacData m_macData;

		private Pfx(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            DerInteger version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            if (!version.HasValue(3))
                throw new ArgumentException("wrong version for PFX PDU");

            m_contentInfo = Asn1Utilities.Read(seq, ref pos, ContentInfo.GetInstance);
            m_macData = Asn1Utilities.ReadOptional(seq, ref pos, MacData.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

		public Pfx(ContentInfo contentInfo, MacData macData)
        {
            m_contentInfo = contentInfo ?? throw new ArgumentNullException(nameof(contentInfo));
            m_macData = macData;
        }

        public ContentInfo AuthSafe => m_contentInfo;

        public MacData MacData => m_macData;

        public override Asn1Object ToAsn1Object()
        {
            return m_macData == null
                ?  new BerSequence(DerInteger.Three, m_contentInfo)
                :  new BerSequence(DerInteger.Three, m_contentInfo, m_macData);
        }
    }
}
