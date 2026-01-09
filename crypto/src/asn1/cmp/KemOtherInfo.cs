using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /*
     * <pre>
     * KemOtherInfo ::= SEQUENCE {
     *   staticString      PKIFreeText,  -- MUST be "CMP-KEM"
     *   transactionID [0] OCTET STRING     OPTIONAL,
     *   senderNonce   [1] OCTET STRING     OPTIONAL,
     *   recipNonce    [2] OCTET STRING     OPTIONAL,
     *   len               INTEGER (1..MAX),
     *   mac               AlgorithmIdentifier{MAC-ALGORITHM, {...}}
     *   ct                OCTET STRING
     * }
     * </pre>
     */
    public class KemOtherInfo
        : Asn1Encodable
    {
        public static KemOtherInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KemOtherInfo kemOtherInfo)
                return kemOtherInfo;
            return new KemOtherInfo(Asn1Sequence.GetInstance(obj));
        }

        public static KemOtherInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemOtherInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static KemOtherInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemOtherInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private static readonly PkiFreeText DEFAULT_staticString = new PkiFreeText("CMP-KEM");

        private readonly PkiFreeText m_staticString;
        private readonly Asn1OctetString m_transactionID;
        private readonly Asn1OctetString m_senderNonce;
        private readonly Asn1OctetString m_recipNonce;
        private readonly DerInteger m_len;
        private readonly AlgorithmIdentifier m_mac;
        private readonly Asn1OctetString m_ct;

        public KemOtherInfo(Asn1OctetString transactionID, Asn1OctetString senderNonce, Asn1OctetString recipNonce,
            DerInteger len, AlgorithmIdentifier mac, Asn1OctetString ct)
        {
            m_staticString = DEFAULT_staticString;
            m_transactionID = transactionID;
            m_senderNonce = senderNonce;
            m_recipNonce = recipNonce;
            m_len = len;
            m_mac = mac;
            m_ct = ct;
        }

        public KemOtherInfo(Asn1OctetString transactionID, Asn1OctetString senderNonce, Asn1OctetString recipNonce,
            long len, AlgorithmIdentifier mac, Asn1OctetString ct)
            : this(transactionID, senderNonce, recipNonce, DerInteger.ValueOf(len), mac, ct)
        {
        }

        private KemOtherInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 4 || count > 7)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_staticString = PkiFreeText.GetInstance(seq[pos++]);
            if (!DEFAULT_staticString.Equals(m_staticString))
                throw new ArgumentException("staticString field should be " + DEFAULT_staticString);

            m_transactionID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1OctetString.GetTagged);
            m_senderNonce = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Asn1OctetString.GetTagged);
            m_recipNonce = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, Asn1OctetString.GetTagged);
            m_len = DerInteger.GetInstance(seq[pos++]);
            m_mac = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_ct = Asn1OctetString.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public virtual Asn1OctetString TransactionID => m_transactionID;

        public virtual Asn1OctetString SenderNonce => m_senderNonce;

        public virtual Asn1OctetString RecipNonce => m_recipNonce;

        public virtual DerInteger Len => m_len;

        public virtual AlgorithmIdentifier Mac => m_mac;

        public virtual Asn1OctetString Ct => m_ct;

        /**
         * <pre>
         * KemOtherInfo ::= SEQUENCE {
         *   staticString      PKIFreeText,   -- MUST be "CMP-KEM"
         *   transactionID [0] OCTET STRING     OPTIONAL,
         *   senderNonce   [1] OCTET STRING     OPTIONAL,
         *   recipNonce    [2] OCTET STRING     OPTIONAL,
         *   len               INTEGER (1..MAX),
         *   mac               AlgorithmIdentifier{MAC-ALGORITHM, {...}}
         *   ct                OCTET STRING
         * }
         * </pre>
         *
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(7);

            v.Add(m_staticString);
            v.AddOptionalTagged(true, 0, m_transactionID);
            v.AddOptionalTagged(true, 1, m_senderNonce);
            v.AddOptionalTagged(true, 2, m_recipNonce);
            v.Add(m_len);
            v.Add(m_mac);
            v.Add(m_ct);

            return new DerSequence(v);
        }
    }
}
