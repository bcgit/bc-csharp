using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class CrlID
        : Asn1Encodable
    {
        public static CrlID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlID crlID)
                return crlID;
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlID(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static CrlID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerIA5String m_crlUrl;
        private readonly DerInteger m_crlNum;
        private readonly Asn1GeneralizedTime m_crlTime;

        [Obsolete("Use 'GetInstance' instead")]
        public CrlID(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_crlUrl = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DerIA5String.GetInstance);
            m_crlNum = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, DerInteger.GetInstance);
            m_crlTime = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, Asn1GeneralizedTime.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DerIA5String CrlUrl => m_crlUrl;

        public DerInteger CrlNum => m_crlNum;

        public Asn1GeneralizedTime CrlTime => m_crlTime;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * CrlID ::= Sequence {
         *     crlUrl               [0]     EXPLICIT IA5String OPTIONAL,
         *     crlNum               [1]     EXPLICIT Integer OPTIONAL,
         *     crlTime              [2]     EXPLICIT GeneralizedTime OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_crlUrl);
            v.AddOptionalTagged(true, 1, m_crlNum);
            v.AddOptionalTagged(true, 2, m_crlTime);
            return new DerSequence(v);
        }
    }
}
