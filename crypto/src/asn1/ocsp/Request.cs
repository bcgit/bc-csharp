using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The Request structure of RFC 6960: a request for the status of one certificate.</summary>
    public class Request
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Request"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Request"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Request"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Request GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Request request)
                return request;
            return new Request(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Request"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Request"/>.</returns>
        public static Request GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new Request(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="Request"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Request"/>.</returns>
        public static Request GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Request(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CertID m_reqCert;
        private readonly X509Extensions m_singleRequestExtensions;

        /// <summary>Create a new <see cref="Request"/>.</summary>
        /// <param name="reqCert">The req cert.</param>
        /// <param name="singleRequestExtensions">The single request extensions.</param>
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

            m_reqCert = Asn1Utilities.Read(seq, ref pos, CertID.GetInstance);
            m_singleRequestExtensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the req cert.</summary>
        public CertID ReqCert => m_reqCert;

        /// <summary>Gets the single request extensions.</summary>
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
