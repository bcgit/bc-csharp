using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The CertRepMessage structure of RFC 4210, the body of the certificate response messages.</summary>
    public class CertRepMessage
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertRepMessage"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertRepMessage"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertRepMessage"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertRepMessage GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertRepMessage certRepMessage)
                return certRepMessage;
            return new CertRepMessage(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertRepMessage"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertRepMessage"/>.</returns>
        public static CertRepMessage GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertRepMessage(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CertRepMessage"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertRepMessage"/>.</returns>
        public static CertRepMessage GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertRepMessage(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_caPubs;
        private readonly Asn1Sequence m_response;

        private CertRepMessage(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_caPubs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Asn1Sequence.GetTagged);
            m_response = Asn1Utilities.Read(seq, ref pos, Asn1Sequence.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CertRepMessage"/>.</summary>
        /// <param name="caPubs">The ca pubs.</param>
        /// <param name="response">The response.</param>
        public CertRepMessage(CmpCertificate[] caPubs, CertResponse[] response)
        {
            if (response == null)
                throw new ArgumentNullException(nameof(response));

            if (caPubs != null && caPubs.Length > 0)
            {
                m_caPubs = new DerSequence(caPubs);
            }

            m_response = new DerSequence(response);
        }

        /// <summary>Return the CA pubs.</summary>
        public virtual CmpCertificate[] GetCAPubs() => m_caPubs?.MapElements(CmpCertificate.GetInstance);

        /// <summary>Return the response.</summary>
        public virtual CertResponse[] GetResponse() => m_response.MapElements(CertResponse.GetInstance);

        /**
         * <pre>
         * CertRepMessage ::= SEQUENCE {
         *                          caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
         *                                                                             OPTIONAL,
         *                          response         SEQUENCE OF CertResponse
         * }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(true, 1, m_caPubs);
            v.Add(m_response);
            return new DerSequence(v);
        }
    }
}
