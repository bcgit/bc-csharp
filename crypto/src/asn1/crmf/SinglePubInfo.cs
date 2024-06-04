using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class SinglePubInfo
        : Asn1Encodable
    {
        public static SinglePubInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SinglePubInfo singlePubInfo)
                return singlePubInfo;
            return new SinglePubInfo(Asn1Sequence.GetInstance(obj));
        }

        public static SinglePubInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new SinglePubInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger m_pubMethod;
        private readonly GeneralName m_pubLocation;

        private SinglePubInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_pubMethod = DerInteger.GetInstance(seq[pos++]);

            if (pos < count)
            {
                m_pubLocation = GeneralName.GetInstance(seq[pos++]);
            }

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public virtual GeneralName PubLocation => m_pubLocation;

        /**
         * <pre>
         * SinglePubInfo ::= SEQUENCE {
         *        pubMethod    INTEGER {
         *           dontCare    (0),
         *           x500        (1),
         *           web         (2),
         *           ldap        (3) },
         *       pubLocation  GeneralName OPTIONAL }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_pubLocation == null
                ?  new DerSequence(m_pubMethod)
                :  new DerSequence(m_pubMethod, m_pubLocation);
        }
    }
}
