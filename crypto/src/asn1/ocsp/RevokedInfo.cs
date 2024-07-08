using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class RevokedInfo
        : Asn1Encodable
    {
        public static RevokedInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RevokedInfo revokedInfo)
                return revokedInfo;
            return new RevokedInfo(Asn1Sequence.GetInstance(obj));
        }

        public static RevokedInfo GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new RevokedInfo(Asn1Sequence.GetInstance(obj, explicitly));

        public static RevokedInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RevokedInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1GeneralizedTime m_revocationTime;
        private readonly CrlReason m_revocationReason;

        public RevokedInfo(Asn1GeneralizedTime revocationTime)
			: this(revocationTime, null)
		{
		}

        public RevokedInfo(Asn1GeneralizedTime revocationTime, CrlReason revocationReason)
        {
			m_revocationTime = revocationTime ?? throw new ArgumentNullException("revocationTime");
            m_revocationReason = revocationReason;
        }

        private RevokedInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_revocationTime = Asn1GeneralizedTime.GetInstance(seq[pos++]);

            m_revocationReason = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true,
                (t, e) => new CrlReason(DerEnumerated.GetTagged(t, e)));

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Asn1GeneralizedTime RevocationTime => m_revocationTime;

        public CrlReason RevocationReason => m_revocationReason;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * RevokedInfo ::= Sequence {
         *      revocationTime              GeneralizedTime,
         *      revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_revocationTime);
            v.AddOptionalTagged(true, 0, m_revocationReason);
            return new DerSequence(v);
        }
    }
}
