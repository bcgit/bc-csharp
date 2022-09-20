using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * GenMsg:    {id-it TBD1}, SEQUENCE SIZE (1..MAX) OF CRLStatus
     * GenRep:    {id-it TBD2}, SEQUENCE SIZE (1..MAX) OF
     * CertificateList  |  &lt; absent &gt;
     * <p>
     * CRLSource ::= CHOICE {
     * dpn          [0] DistributionPointName,
     * issuer       [1] GeneralNames }
     * <p>
     */
    public class CrlSource
        : Asn1Encodable, IAsn1Choice
    {
        public static CrlSource GetInstance(object obj)
        {
            if (obj is CrlSource crlSource)
                return crlSource;

            if (obj != null)
                return new CrlSource(Asn1TaggedObject.GetInstance(obj));

            return null;
        }

        private readonly DistributionPointName m_dpn;
        private readonly GeneralNames m_issuer;

        private CrlSource(Asn1TaggedObject taggedObject)
        {
            switch (taggedObject.TagNo)
            {
            case 0:
                m_dpn = DistributionPointName.GetInstance(taggedObject, true);
                m_issuer = null;
                break;
            case 1:
                m_dpn = null;
                m_issuer = GeneralNames.GetInstance(taggedObject, true);
                break;
            default:
                throw new ArgumentException("unknown tag: " + Asn1Utilities.GetTagText(taggedObject));
            }
        }

        public CrlSource(DistributionPointName dpn, GeneralNames issuer)
        {
            if ((dpn == null) == (issuer == null))
                throw new ArgumentException("either dpn or issuer must be set");

            m_dpn = dpn;
            m_issuer = issuer;
        }

        public virtual DistributionPointName Dpn => m_dpn;

        public virtual GeneralNames Issuer => m_issuer;

        public override Asn1Object ToAsn1Object()
        {
            if (m_dpn != null)
                return new DerTaggedObject(true, 0, m_dpn);

            return new DerTaggedObject(true, 1, m_issuer);
        }
    }
}
