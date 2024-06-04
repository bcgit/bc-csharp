using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class PopoSigningKey
        : Asn1Encodable
    {
        public static PopoSigningKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PopoSigningKey popoSigningKey)
                return popoSigningKey;
            return new PopoSigningKey(Asn1Sequence.GetInstance(obj));
        }

        public static PopoSigningKey GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
            return new PopoSigningKey(Asn1Sequence.GetInstance(obj, isExplicit));
        }

        private readonly PopoSigningKeyInput m_poposkInput;
        private readonly AlgorithmIdentifier m_algorithmIdentifier;
        private readonly DerBitString m_signature;

        private PopoSigningKey(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_poposkInput = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, PopoSigningKeyInput.GetInstance);
            m_algorithmIdentifier = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_signature = DerBitString.GetInstance(seq[pos++]);

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

        public virtual PopoSigningKeyInput PoposkInput => m_poposkInput;

        public virtual AlgorithmIdentifier AlgorithmIdentifier => m_algorithmIdentifier;

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
