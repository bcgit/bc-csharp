using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class CertId
        : Asn1Encodable
    {
        public static CertId GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertId certId)
                return certId;
            return new CertId(Asn1Sequence.GetInstance(obj));
        }

        public static CertId GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new CertId(Asn1Sequence.GetInstance(obj, isExplicit));

        public static CertId GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertId(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly GeneralName m_issuer;
        private readonly DerInteger m_serialNumber;

        private CertId(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_issuer = GeneralName.GetInstance(seq[0]);
            m_serialNumber = DerInteger.GetInstance(seq[1]);
        }

        public CertId(GeneralName issuer, DerInteger serialNumber)
        {
            m_issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            m_serialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
        }

        public virtual GeneralName Issuer => m_issuer;

        public virtual DerInteger SerialNumber => m_serialNumber;

        /**
         * <pre>
         * CertId ::= SEQUENCE {
         *                 issuer           GeneralName,
         *                 serialNumber     INTEGER }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_issuer, m_serialNumber);
    }
}
