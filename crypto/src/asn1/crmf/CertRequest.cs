using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>
    /// The CertRequest structure of RFC 4211: a request identifier, a certificate template and controls.
    /// </summary>
    public class CertRequest
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertRequest"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertRequest"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertRequest"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertRequest GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertRequest certRequest)
                return certRequest;
            return new CertRequest(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertRequest"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertRequest"/>.</returns>
        public static CertRequest GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertRequest(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CertRequest"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertRequest"/>.</returns>
        public static CertRequest GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertRequest(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_certReqId;
        private readonly CertTemplate m_certTemplate;
        private readonly Controls m_controls;

        private CertRequest(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_certReqId = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_certTemplate = Asn1Utilities.Read(seq, ref pos, CertTemplate.GetInstance);
            m_controls = Asn1Utilities.ReadOptional(seq, ref pos, Controls.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CertRequest"/>.</summary>
        /// <param name="certReqId">The cert req id.</param>
        /// <param name="certTemplate">The cert template.</param>
        /// <param name="controls">The controls.</param>
        public CertRequest(int certReqId, CertTemplate certTemplate, Controls controls)
            : this(DerInteger.ValueOf(certReqId), certTemplate, controls)
        {
        }

        /// <summary>Create a new <see cref="CertRequest"/>.</summary>
        /// <param name="certReqId">The cert req id.</param>
        /// <param name="certTemplate">The cert template.</param>
        /// <param name="controls">The controls.</param>
        public CertRequest(DerInteger certReqId, CertTemplate certTemplate, Controls controls)
        {
            m_certReqId = certReqId ?? throw new ArgumentNullException(nameof(certReqId));
            m_certTemplate = certTemplate ?? throw new ArgumentNullException(nameof(certTemplate));
            m_controls = controls;
        }

        /// <summary>Gets the cert req ID.</summary>
        public virtual DerInteger CertReqID => m_certReqId;

        /// <summary>Gets the cert template.</summary>
        public virtual CertTemplate CertTemplate => m_certTemplate;

        /// <summary>Gets the controls.</summary>
        public virtual Controls Controls => m_controls;

        /**
         * <pre>
         * CertRequest ::= SEQUENCE {
         *                      certReqId     INTEGER,          -- ID for matching request and reply
         *                      certTemplate  CertTemplate,  -- Selected fields of cert to be issued
         *                      controls      Controls OPTIONAL }   -- Attributes affecting issuance
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_certReqId, m_certTemplate);
            v.AddOptional(m_controls);
            return new DerSequence(v);
        }
    }
}
