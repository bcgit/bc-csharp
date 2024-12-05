using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class SingleResponse
        : Asn1Encodable
    {
        public static SingleResponse GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SingleResponse singleResponse)
                return singleResponse;
#pragma warning disable CS0618 // Type or member is obsolete
            return new SingleResponse(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static SingleResponse GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SingleResponse(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static SingleResponse GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SingleResponse(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly CertID m_certID;
        private readonly CertStatus m_certStatus;
        private readonly Asn1GeneralizedTime m_thisUpdate;
        private readonly Asn1GeneralizedTime m_nextUpdate;
        private readonly X509Extensions m_singleExtensions;

        public SingleResponse(CertID certID, CertStatus certStatus, Asn1GeneralizedTime thisUpdate,
            Asn1GeneralizedTime nextUpdate, X509Extensions singleExtensions)
        {
            m_certID = certID ?? throw new ArgumentNullException(nameof(certID));
            m_certStatus = certStatus ?? throw new ArgumentNullException(nameof(certStatus));
            m_thisUpdate = thisUpdate ?? throw new ArgumentNullException(nameof(thisUpdate));
            m_nextUpdate = nextUpdate;
            m_singleExtensions = singleExtensions;
        }

        [Obsolete("Use 'GetInstance' instead")]
        public SingleResponse(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 3 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_certID = CertID.GetInstance(seq[pos++]);
            m_certStatus = CertStatus.GetInstance(seq[pos++]);
            m_thisUpdate = Asn1GeneralizedTime.GetInstance(seq[pos++]);
            m_nextUpdate = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1GeneralizedTime.GetTagged);
            m_singleExtensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public CertID CertId => m_certID;

        public CertStatus CertStatus => m_certStatus;

        public Asn1GeneralizedTime ThisUpdate => m_thisUpdate;

        public Asn1GeneralizedTime NextUpdate => m_nextUpdate;

        public X509Extensions SingleExtensions => m_singleExtensions;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  SingleResponse ::= Sequence {
         *          certID                       CertID,
         *          certStatus                   CertStatus,
         *          thisUpdate                   GeneralizedTime,
         *          nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
         *          singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_certID, m_certStatus, m_thisUpdate);
            v.AddOptionalTagged(true, 0, m_nextUpdate);
            v.AddOptionalTagged(true, 1, m_singleExtensions);
            return new DerSequence(v);
        }
    }
}
