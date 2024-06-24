using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class TbsRequest
        : Asn1Encodable
    {
        public static TbsRequest GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TbsRequest tbsRequest)
                return tbsRequest;
            return new TbsRequest(Asn1Sequence.GetInstance(obj));
        }

        public static TbsRequest GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new TbsRequest(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private static readonly DerInteger V1 = DerInteger.Zero;

        private readonly DerInteger m_version;
        private readonly bool m_versionPresent;
        private readonly GeneralName m_requestorName;
        private readonly Asn1Sequence m_requestList;
        private readonly X509Extensions m_requestExtensions;

        public TbsRequest(GeneralName requestorName, Asn1Sequence requestList, X509Extensions requestExtensions)
        {
            m_version = V1;
            m_versionPresent = false;
            m_requestorName = requestorName;
            m_requestList = requestList ?? throw new ArgumentNullException(nameof(requestList));
            m_requestExtensions = requestExtensions;
        }

        private TbsRequest(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            {
                DerInteger version = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DerInteger.GetTagged);

                m_version = version ?? V1;
                m_versionPresent = version != null;
            }

            m_requestorName = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, GeneralName.GetTagged);
			m_requestList = Asn1Sequence.GetInstance(seq[pos++]);
            m_requestExtensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DerInteger Version => m_version;

        public GeneralName RequestorName => m_requestorName;

        public Asn1Sequence RequestList => m_requestList;

        public X509Extensions RequestExtensions => m_requestExtensions;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * TBSRequest      ::=     Sequence {
         *     version             [0]     EXPLICIT Version DEFAULT v1,
         *     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
         *     requestList                 Sequence OF Request,
         *     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);

            //
            // if default don't include - unless explicitly provided. Not strictly correct
            // but required for some requests
            //
            if (m_versionPresent || !V1.Equals(m_version))
            {
                v.Add(new DerTaggedObject(true, 0, m_version));
            }

            v.AddOptionalTagged(true, 1, m_requestorName);
            v.Add(m_requestList);
            v.AddOptionalTagged(true, 2, m_requestExtensions);
            return new DerSequence(v);
        }
    }
}
