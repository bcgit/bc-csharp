using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The PKIHeader structure of RFC 4210, the header of a CMP message.</summary>
    public class PkiHeader
        : Asn1Encodable
    {
        /**
         * Value for a "null" recipient or sender.
         */
        public static readonly GeneralName NULL_NAME = new GeneralName(X509Name.GetInstance(DerSequence.Empty));

        /// <summary>The value of the version field for CMP 1999 (RFC 2510).</summary>
        public static readonly int CMP_1999 = 1;
        /// <summary>The value of the version field for CMP 2000 (RFC 4210).</summary>
        public static readonly int CMP_2000 = 2;

        /// <summary>Return an <see cref="PkiHeader"/> from the given object.</summary>
        /// <param name="obj">An <see cref="PkiHeader"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="PkiHeader"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PkiHeader GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiHeader pkiHeader)
                return pkiHeader;
            return new PkiHeader(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PkiHeader"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiHeader"/>.</returns>
        public static PkiHeader GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiHeader(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PkiHeader"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiHeader"/>.</returns>
        public static PkiHeader GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiHeader(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_pvno;
        private readonly GeneralName m_sender;
        private readonly GeneralName m_recipient;
        private readonly Asn1GeneralizedTime m_messageTime;
        private readonly AlgorithmIdentifier m_protectionAlg;
        private readonly Asn1OctetString m_senderKID;       // KeyIdentifier
        private readonly Asn1OctetString m_recipKID;        // KeyIdentifier
        private readonly Asn1OctetString m_transactionID;
        private readonly Asn1OctetString m_senderNonce;
        private readonly Asn1OctetString m_recipNonce;
        private readonly PkiFreeText m_freeText;
        private readonly Asn1Sequence m_generalInfo;

        private PkiHeader(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 12)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_pvno = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_sender = Asn1Utilities.Read(seq, ref pos, GeneralName.GetInstance);
            m_recipient = Asn1Utilities.Read(seq, ref pos, GeneralName.GetInstance);
            m_messageTime = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1GeneralizedTime.GetTagged);
            m_protectionAlg = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, AlgorithmIdentifier.GetTagged);
            m_senderKID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, Asn1OctetString.GetTagged);
            m_recipKID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, true, Asn1OctetString.GetTagged);
            m_transactionID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 4, true, Asn1OctetString.GetTagged);
            m_senderNonce = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 5, true, Asn1OctetString.GetTagged);
            m_recipNonce = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 6, true, Asn1OctetString.GetTagged);
            m_freeText = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 7, true, PkiFreeText.GetTagged);
            m_generalInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 8, true, Asn1Sequence.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="PkiHeader"/>.</summary>
        /// <param name="pvno">The pvno.</param>
        /// <param name="sender">The sender.</param>
        /// <param name="recipient">The recipient.</param>
        public PkiHeader(int pvno, GeneralName sender, GeneralName recipient)
            : this(DerInteger.ValueOf(pvno), sender, recipient)
        {
        }

        private PkiHeader(DerInteger pvno, GeneralName sender, GeneralName recipient)
        {
            m_pvno = pvno ?? throw new ArgumentNullException(nameof(pvno));
            m_sender = sender ?? throw new ArgumentNullException(nameof(sender));
            m_recipient = recipient ?? throw new ArgumentNullException(nameof(recipient));
        }

        /// <summary>Gets the pvno.</summary>
        public virtual DerInteger Pvno => m_pvno;

        /// <summary>Gets the sender.</summary>
        public virtual GeneralName Sender => m_sender;

        /// <summary>Gets the recipient.</summary>
        public virtual GeneralName Recipient => m_recipient;

        /// <summary>Gets the message time.</summary>
        public virtual Asn1GeneralizedTime MessageTime => m_messageTime;

        /// <summary>Gets the protection alg.</summary>
        public virtual AlgorithmIdentifier ProtectionAlg => m_protectionAlg;

        /// <summary>Gets the sender KID.</summary>
        public virtual Asn1OctetString SenderKID => m_senderKID;

        /// <summary>Gets the recip KID.</summary>
        public virtual Asn1OctetString RecipKID => m_recipKID;

        /// <summary>Gets the transaction ID.</summary>
        public virtual Asn1OctetString TransactionID => m_transactionID;

        /// <summary>Gets the sender nonce.</summary>
        public virtual Asn1OctetString SenderNonce => m_senderNonce;

        /// <summary>Gets the recip nonce.</summary>
        public virtual Asn1OctetString RecipNonce => m_recipNonce;

        /// <summary>Gets the free text.</summary>
        public virtual PkiFreeText FreeText => m_freeText;

        /// <summary>Return the general info.</summary>
        public virtual InfoTypeAndValue[] GetGeneralInfo() => m_generalInfo?.MapElements(InfoTypeAndValue.GetInstance);

        /**
         * <pre>
         *  PkiHeader ::= SEQUENCE {
         *            pvno                INTEGER     { cmp1999(1), cmp2000(2) },
         *            sender              GeneralName,
         *            -- identifies the sender
         *            recipient           GeneralName,
         *            -- identifies the intended recipient
         *            messageTime     [0] GeneralizedTime         OPTIONAL,
         *            -- time of production of this message (used when sender
         *            -- believes that the transport will be "suitable"; i.e.,
         *            -- that the time will still be meaningful upon receipt)
         *            protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
         *            -- algorithm used for calculation of protection bits
         *            senderKID       [2] KeyIdentifier           OPTIONAL,
         *            recipKID        [3] KeyIdentifier           OPTIONAL,
         *            -- to identify specific keys used for protection
         *            transactionID   [4] OCTET STRING            OPTIONAL,
         *            -- identifies the transaction; i.e., this will be the same in
         *            -- corresponding request, response, certConf, and PKIConf
         *            -- messages
         *            senderNonce     [5] OCTET STRING            OPTIONAL,
         *            recipNonce      [6] OCTET STRING            OPTIONAL,
         *            -- nonces used to provide replay protection, senderNonce
         *            -- is inserted by the creator of this message; recipNonce
         *            -- is a nonce previously inserted in a related message by
         *            -- the intended recipient of this message
         *            freeText        [7] PKIFreeText             OPTIONAL,
         *            -- this may be used to indicate context-specific instructions
         *            -- (this field is intended for human consumption)
         *            generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
         *                                 InfoTypeAndValue     OPTIONAL
         *            -- this may be used to convey context-specific information
         *            -- (this field not primarily intended for human consumption)
         * }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(12);
            v.Add(m_pvno, m_sender, m_recipient);
            v.AddOptionalTagged(true, 0, m_messageTime);
            v.AddOptionalTagged(true, 1, m_protectionAlg);
            v.AddOptionalTagged(true, 2, m_senderKID);
            v.AddOptionalTagged(true, 3, m_recipKID);
            v.AddOptionalTagged(true, 4, m_transactionID);
            v.AddOptionalTagged(true, 5, m_senderNonce);
            v.AddOptionalTagged(true, 6, m_recipNonce);
            v.AddOptionalTagged(true, 7, m_freeText);
            v.AddOptionalTagged(true, 8, m_generalInfo);
            return new DerSequence(v);
        }
    }
}
