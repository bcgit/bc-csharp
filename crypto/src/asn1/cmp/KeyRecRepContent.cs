using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The KeyRecRepContent structure of RFC 4210, the body of a key recovery response.</summary>
    public class KeyRecRepContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="KeyRecRepContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="KeyRecRepContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="KeyRecRepContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static KeyRecRepContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KeyRecRepContent keyRecRepContent)
                return keyRecRepContent;
            return new KeyRecRepContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="KeyRecRepContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KeyRecRepContent"/>.</returns>
        public static KeyRecRepContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KeyRecRepContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="KeyRecRepContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KeyRecRepContent"/>.</returns>
        public static KeyRecRepContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KeyRecRepContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly PkiStatusInfo m_status;
        private readonly CmpCertificate m_newSigCert;
        private readonly Asn1Sequence m_caCerts;
        private readonly Asn1Sequence m_keyPairHist;

        private KeyRecRepContent(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_status = Asn1Utilities.Read(seq, ref pos, PkiStatusInfo.GetInstance);
            m_newSigCert = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, CmpCertificate.GetTagged);
            m_caCerts = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Asn1Sequence.GetTagged);
            m_keyPairHist = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, Asn1Sequence.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the status.</summary>
        public virtual PkiStatusInfo Status => m_status;

        /// <summary>Gets the new sig cert.</summary>
        public virtual CmpCertificate NewSigCert => m_newSigCert;

        /// <summary>Return the CA certs.</summary>
        public virtual CmpCertificate[] GetCACerts() => m_caCerts?.MapElements(CmpCertificate.GetInstance);

        /// <summary>Return the key pair hist.</summary>
        public virtual CertifiedKeyPair[] GetKeyPairHist() => m_keyPairHist?.MapElements(CertifiedKeyPair.GetInstance);

        /**
         * <pre>
         * KeyRecRepContent ::= SEQUENCE {
         *                         status                  PKIStatusInfo,
         *                         newSigCert          [0] CMPCertificate OPTIONAL,
         *                         caCerts             [1] SEQUENCE SIZE (1..MAX) OF
         *                                                           CMPCertificate OPTIONAL,
         *                         keyPairHist         [2] SEQUENCE SIZE (1..MAX) OF
         *                                                           CertifiedKeyPair OPTIONAL
         *              }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_status);
            v.AddOptionalTagged(true, 0, m_newSigCert);
            v.AddOptionalTagged(true, 1, m_caCerts);
            v.AddOptionalTagged(true, 2, m_keyPairHist);
            return new DerSequence(v);
        }
    }
}
