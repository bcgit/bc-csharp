using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     *      ErrorMsgContent ::= SEQUENCE {
     *          pKIStatusInfo          PKIStatusInfo,
     *          errorCode              INTEGER           OPTIONAL,
     *          -- implementation-specific error codes
     *          errorDetails           PKIFreeText       OPTIONAL
     *          -- implementation-specific error details
     *      }
     * </pre>
     */
    public class ErrorMsgContent
		: Asn1Encodable
	{
        public static ErrorMsgContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ErrorMsgContent errorMsgContent)
                return errorMsgContent;
            return new ErrorMsgContent(Asn1Sequence.GetInstance(obj));
        }

        public static ErrorMsgContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new ErrorMsgContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly PkiStatusInfo m_pkiStatusInfo;
		private readonly DerInteger m_errorCode;
		private readonly PkiFreeText m_errorDetails;

		private ErrorMsgContent(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_pkiStatusInfo = PkiStatusInfo.GetInstance(seq[pos++]);
			m_errorCode = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);
            m_errorDetails = Asn1Utilities.ReadOptional(seq, ref pos, PkiFreeText.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

		public ErrorMsgContent(PkiStatusInfo pkiStatusInfo)
			: this(pkiStatusInfo, null, null)
		{
		}

		public ErrorMsgContent(PkiStatusInfo pkiStatusInfo, DerInteger errorCode, PkiFreeText errorDetails)
		{
			m_pkiStatusInfo = pkiStatusInfo ?? throw new ArgumentNullException(nameof(pkiStatusInfo));
			m_errorCode = errorCode;
			m_errorDetails = errorDetails;
		}

		public virtual PkiStatusInfo PkiStatusInfo => m_pkiStatusInfo;

		public virtual DerInteger ErrorCode => m_errorCode;

		public virtual PkiFreeText ErrorDetails => m_errorDetails;

		/**
		 * <pre>
		 * ErrorMsgContent ::= SEQUENCE {
		 *                        pKIStatusInfo          PKIStatusInfo,
		 *                        errorCode              INTEGER           OPTIONAL,
		 *                        -- implementation-specific error codes
		 *                        errorDetails           PKIFreeText       OPTIONAL
		 *                        -- implementation-specific error details
		 * }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
			v.Add(m_pkiStatusInfo);
			v.AddOptional(m_errorCode, m_errorDetails);
			return new DerSequence(v);
		}
	}
}
