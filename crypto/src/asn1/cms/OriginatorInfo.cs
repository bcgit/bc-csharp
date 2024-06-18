using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class OriginatorInfo
        : Asn1Encodable
    {
        public static OriginatorInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OriginatorInfo originatorInfo)
                return originatorInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new OriginatorInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static OriginatorInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new OriginatorInfo(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1Set m_certs;
        private readonly Asn1Set m_crls;

        public OriginatorInfo(Asn1Set certs, Asn1Set crls)
        {
            m_certs = certs;
            m_crls = crls;
        }

        [Obsolete("Use 'GetInstance' instead")]
        public OriginatorInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1Set.GetInstance);
            m_crls = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Asn1Set Certificates => m_certs;

        public Asn1Set Crls => m_crls;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OriginatorInfo ::= Sequence {
         *     certs [0] IMPLICIT CertificateSet OPTIONAL,
         *     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(false, 0, m_certs);
            v.AddOptionalTagged(false, 1, m_crls);
			return new DerSequence(v);
        }
    }
}
