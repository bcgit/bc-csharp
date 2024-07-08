using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class Request
        : Asn1Encodable
    {
        public static Request GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Request request)
                return request;
            return new Request(Asn1Sequence.GetInstance(obj));
        }

        public static Request GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new Request(Asn1Sequence.GetInstance(obj, explicitly));

        public static Request GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Request(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CertID m_reqCert;
        private readonly X509Extensions m_singleRequestExtensions;

        public Request(CertID reqCert, X509Extensions singleRequestExtensions)
        {
			m_reqCert = reqCert ?? throw new ArgumentNullException(nameof(reqCert));
            m_singleRequestExtensions = singleRequestExtensions;
        }

		private Request(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_reqCert = CertID.GetInstance(seq[pos++]);
            m_singleRequestExtensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public CertID ReqCert => m_reqCert;

        public X509Extensions SingleRequestExtensions => m_singleRequestExtensions;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * Request         ::=     Sequence {
         *     reqCert                     CertID,
         *     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_reqCert);
            v.AddOptionalTagged(true, 0, m_singleRequestExtensions);
            return new DerSequence(v);
        }
    }
}
