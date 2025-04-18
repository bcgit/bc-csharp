using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.BC
{
    /**
     * Extension to tie an alternate certificate to the containing certificate.
     * <pre>
     *     LinkedCertificate := SEQUENCE {
     *         digest        DigestInfo,                   -- digest of PQC certificate
     *         certLocation  GeneralName,                  -- location of PQC certificate
     *         certIssuer    [0] Name OPTIONAL,            -- issuer of PQC cert (if different from current certificate)
     *         cACerts       [1] GeneralNames OPTIONAL,    -- CA certificates for PQC cert (one of more locations)
     * }
     * </pre>
     */
    public class LinkedCertificate
        : Asn1Encodable
    {
        public static LinkedCertificate GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is LinkedCertificate linkedCertificate)
                return linkedCertificate;
            return new LinkedCertificate(Asn1Sequence.GetInstance(obj));
        }

        public static LinkedCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new LinkedCertificate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static LinkedCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new LinkedCertificate(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DigestInfo m_digest;
        private readonly GeneralName m_certLocation;
        private readonly X509Name m_certIssuer;
        private readonly GeneralNames m_cACerts;

        public LinkedCertificate(DigestInfo digest, GeneralName certLocation)
            : this(digest, certLocation, null, null)
        {
        }

        public LinkedCertificate(DigestInfo digest, GeneralName certLocation, X509Name certIssuer, GeneralNames caCerts)
        {
            m_digest = digest ?? throw new ArgumentNullException(nameof(digest));
            m_certLocation = certLocation ?? throw new ArgumentNullException(nameof(certLocation));
            m_certIssuer = certIssuer;
            m_cACerts = caCerts;
        }

        private LinkedCertificate(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_digest = DigestInfo.GetInstance(seq[pos++]);
            m_certLocation = GeneralName.GetInstance(seq[pos++]);
            m_certIssuer = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, X509Name.GetTagged);
            m_cACerts = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, GeneralNames.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public virtual DigestInfo Digest => m_digest;

        public virtual GeneralName CertLocation => m_certLocation;

        public virtual X509Name CertIssuer => m_certIssuer;

        public virtual GeneralNames CACerts => m_cACerts;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_digest, m_certLocation);
            v.AddOptionalTagged(false, 0, m_certIssuer);
            v.AddOptionalTagged(false, 1, m_cACerts);
            return new DerSequence(v);
        }
    }
}
