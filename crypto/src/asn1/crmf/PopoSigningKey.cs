using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The POPOSigningKey structure of RFC 4211: proof of possession by signature.</summary>
    public class PopoSigningKey
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PopoSigningKey"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PopoSigningKey"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PopoSigningKey"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PopoSigningKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PopoSigningKey popoSigningKey)
                return popoSigningKey;
            return new PopoSigningKey(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PopoSigningKey"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PopoSigningKey"/>.</returns>
        public static PopoSigningKey GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new PopoSigningKey(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="PopoSigningKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PopoSigningKey"/>.</returns>
        public static PopoSigningKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PopoSigningKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly PopoSigningKeyInput m_poposkInput;
        private readonly AlgorithmIdentifier m_algorithmIdentifier;
        private readonly DerBitString m_signature;

        private PopoSigningKey(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_poposkInput = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, PopoSigningKeyInput.GetTagged);
            m_algorithmIdentifier = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_signature = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /**
         * Creates a new Proof of Possession object for a signing key.
         * @param poposkIn the PopoSigningKeyInput structure, or null if the
         *     CertTemplate includes both subject and publicKey values.
         * @param aid the AlgorithmIdentifier used to sign the proof of possession.
         * @param signature a signature over the DER-encoded value of poposkIn,
         *     or the DER-encoded value of certReq if poposkIn is null.
         */
        public PopoSigningKey(PopoSigningKeyInput poposkIn, AlgorithmIdentifier aid, DerBitString signature)
        {
            m_poposkInput = poposkIn;
            m_algorithmIdentifier = aid ?? throw new ArgumentNullException(nameof(aid));
            m_signature = signature ?? throw new ArgumentNullException(nameof(signature));
        }

        /// <summary>Gets the poposk input.</summary>
        public virtual PopoSigningKeyInput PoposkInput => m_poposkInput;

        public virtual AlgorithmIdentifier AlgorithmIdentifier => m_algorithmIdentifier;

        /// <summary>Gets the signature.</summary>
        public virtual DerBitString Signature => m_signature;

        /**
         * <pre>
         * PopoSigningKey ::= SEQUENCE {
         *                      poposkInput           [0] PopoSigningKeyInput OPTIONAL,
         *                      algorithmIdentifier   AlgorithmIdentifier,
         *                      signature             BIT STRING }
         *  -- The signature (using "algorithmIdentifier") is on the
         *  -- DER-encoded value of poposkInput.  NOTE: If the CertReqMsg
         *  -- certReq CertTemplate contains the subject and publicKey values,
         *  -- then poposkInput MUST be omitted and the signature MUST be
         *  -- computed on the DER-encoded value of CertReqMsg certReq.  If
         *  -- the CertReqMsg certReq CertTemplate does not contain the public
         *  -- key and subject values, then poposkInput MUST be present and
         *  -- MUST be signed.  This strategy ensures that the public key is
         *  -- not present in both the poposkInput and CertReqMsg certReq
         *  -- CertTemplate fields.
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(false, 0, m_poposkInput);
            v.Add(m_algorithmIdentifier);
            v.Add(m_signature);
            return new DerSequence(v);
        }
    }
}
