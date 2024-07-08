using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class PkiHeaderBuilder
	{
		private readonly DerInteger pvno;
		private readonly GeneralName sender;
		private readonly GeneralName recipient;
		private Asn1GeneralizedTime messageTime;
		private AlgorithmIdentifier protectionAlg;
		private Asn1OctetString senderKID;       // KeyIdentifier
		private Asn1OctetString recipKID;        // KeyIdentifier
		private Asn1OctetString transactionID;
		private Asn1OctetString senderNonce;
		private Asn1OctetString recipNonce;
		private PkiFreeText     freeText;
		private Asn1Sequence    generalInfo;

        public PkiHeaderBuilder(int pvno, GeneralName sender, GeneralName recipient)
            : this(new DerInteger(pvno), sender, recipient)
        {
        }

        private PkiHeaderBuilder(DerInteger pvno, GeneralName sender, GeneralName recipient)
        {
            this.pvno = pvno ?? throw new ArgumentNullException(nameof(pvno));
			this.sender = sender ?? throw new ArgumentNullException(nameof(sender));
			this.recipient = recipient ?? throw new ArgumentNullException(nameof(recipient));
		}

		public virtual PkiHeaderBuilder SetMessageTime(Asn1GeneralizedTime time)
		{
			messageTime = time;
			return this;
		}

		public virtual PkiHeaderBuilder SetProtectionAlg(AlgorithmIdentifier aid)
		{
			protectionAlg = aid;
			return this;
		}

		public virtual PkiHeaderBuilder SetSenderKID(byte[] kid)
		{
            return SetSenderKID(DerOctetString.FromContentsOptional(kid));
		}

		public virtual PkiHeaderBuilder SetSenderKID(Asn1OctetString kid)
		{
			senderKID = kid;
			return this;
		}

		public virtual PkiHeaderBuilder SetRecipKID(byte[] kid)
		{
            return SetRecipKID(DerOctetString.FromContentsOptional(kid));
		}

		public virtual PkiHeaderBuilder SetRecipKID(Asn1OctetString kid)
		{
			recipKID = kid;
			return this;
		}

		public virtual PkiHeaderBuilder SetTransactionID(byte[] tid)
		{
			return SetTransactionID(DerOctetString.FromContentsOptional(tid));
		}

		public virtual PkiHeaderBuilder SetTransactionID(Asn1OctetString tid)
		{
			transactionID = tid;
			return this;
		}
		
		public virtual PkiHeaderBuilder SetSenderNonce(byte[] nonce)
		{
            return SetSenderNonce(DerOctetString.FromContentsOptional(nonce));
		}

		public virtual PkiHeaderBuilder SetSenderNonce(Asn1OctetString nonce)
		{
			senderNonce = nonce;
			return this;
		}

		public virtual PkiHeaderBuilder SetRecipNonce(byte[] nonce)
		{
            return SetRecipNonce(DerOctetString.FromContentsOptional(nonce));
		}

		public virtual PkiHeaderBuilder SetRecipNonce(Asn1OctetString nonce)
		{
			recipNonce = nonce;
			return this;
		}

		public virtual PkiHeaderBuilder SetFreeText(PkiFreeText text)
		{
			freeText = text;
			return this;
		}
		
		public virtual PkiHeaderBuilder SetGeneralInfo(InfoTypeAndValue genInfo)
		{
			return SetGeneralInfo(MakeGeneralInfoSeq(genInfo));
		}
		
		public virtual PkiHeaderBuilder SetGeneralInfo(InfoTypeAndValue[] genInfos)
		{
			return SetGeneralInfo(MakeGeneralInfoSeq(genInfos));
		}
		
		public virtual PkiHeaderBuilder SetGeneralInfo(Asn1Sequence seqOfInfoTypeAndValue)
		{
			generalInfo = seqOfInfoTypeAndValue;
			return this;
		}

		private static Asn1Sequence MakeGeneralInfoSeq(InfoTypeAndValue generalInfo) => new DerSequence(generalInfo);

		private static Asn1Sequence MakeGeneralInfoSeq(InfoTypeAndValue[] generalInfos) =>
			DerSequence.FromElementsOptional(generalInfos);

		/**
		 * <pre>
		 *  PKIHeader ::= SEQUENCE {
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
		public virtual PkiHeader Build()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(12);
			v.Add(pvno, sender, recipient);
            v.AddOptionalTagged(true, 0, messageTime);
            v.AddOptionalTagged(true, 1, protectionAlg);
			v.AddOptionalTagged(true, 2, senderKID);
			v.AddOptionalTagged(true, 3, recipKID);
			v.AddOptionalTagged(true, 4, transactionID);
			v.AddOptionalTagged(true, 5, senderNonce);
			v.AddOptionalTagged(true, 6, recipNonce);
			v.AddOptionalTagged(true, 7, freeText);
			v.AddOptionalTagged(true, 8, generalInfo);

			messageTime = null;
			protectionAlg = null;
			senderKID = null;
			recipKID = null;
			transactionID = null;
			senderNonce = null;
			recipNonce = null;
			freeText = null;
			generalInfo = null;

			return PkiHeader.GetInstance(new DerSequence(v));
		}
	}
}
