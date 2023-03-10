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
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly PkiStatusInfo m_pkiStatusInfo;
		private readonly DerInteger m_errorCode;
		private readonly PkiFreeText m_errorDetails;

		private ErrorMsgContent(Asn1Sequence seq)
		{
			m_pkiStatusInfo = PkiStatusInfo.GetInstance(seq[0]);

			for (int pos = 1; pos < seq.Count; ++pos)
			{
				Asn1Encodable ae = seq[pos];
				if (ae is DerInteger)
				{
					m_errorCode = DerInteger.GetInstance(ae);
				}
				else
				{
					m_errorDetails = PkiFreeText.GetInstance(ae);
				}
			}
		}

		public ErrorMsgContent(PkiStatusInfo pkiStatusInfo)
			: this(pkiStatusInfo, null, null)
		{
		}

		public ErrorMsgContent(
			PkiStatusInfo	pkiStatusInfo,
			DerInteger		errorCode,
			PkiFreeText		errorDetails)
		{
			if (pkiStatusInfo == null)
				throw new ArgumentNullException(nameof(pkiStatusInfo));

			m_pkiStatusInfo = pkiStatusInfo;
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
			Asn1EncodableVector v = new Asn1EncodableVector(m_pkiStatusInfo);
			v.AddOptional(m_errorCode, m_errorDetails);
			return new DerSequence(v);
		}
	}
}
