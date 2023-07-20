using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class PkiStatusInfo
		: Asn1Encodable
	{
        public static PkiStatusInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiStatusInfo pkiStatusInfo)
                return pkiStatusInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new PkiStatusInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static PkiStatusInfo GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new PkiStatusInfo(Asn1Sequence.GetInstance(obj, isExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_status;
		private readonly PkiFreeText m_statusString;
		private readonly DerBitString m_failInfo;

        [Obsolete("Use 'GetInstance' instead")]
        public PkiStatusInfo(Asn1Sequence seq)
		{
			m_status = DerInteger.GetInstance(seq[0]);

			m_statusString = null;
			m_failInfo = null;

			if (seq.Count > 2)
			{
				m_statusString = PkiFreeText.GetInstance(seq[1]);
				m_failInfo = DerBitString.GetInstance(seq[2]);
			}
			else if (seq.Count > 1)
			{
				object obj = seq[1];
				if (obj is DerBitString)
				{
					m_failInfo = DerBitString.GetInstance(obj);
				}
				else
				{
					m_statusString = PkiFreeText.GetInstance(obj);
				}
			}
		}

		public PkiStatusInfo(int status)
		{
			m_status = new DerInteger(status);
			m_statusString = null;
			m_failInfo = null;
		}

		public PkiStatusInfo(int status, PkiFreeText statusString)
		{
			m_status = new DerInteger(status);
			m_statusString = statusString;
            m_failInfo = null;
        }

        public PkiStatusInfo(int status, PkiFreeText statusString, PkiFailureInfo failInfo)
        {
            m_status = new DerInteger(status);
			m_statusString = statusString;
			m_failInfo = failInfo;
		}

		public BigInteger Status => m_status.Value;

		public PkiFreeText StatusString => m_statusString;

		public DerBitString FailInfo => m_failInfo;

		/**
		 * <pre>
		 * PkiStatusInfo ::= SEQUENCE {
		 *     status        PKIStatus,                (INTEGER)
		 *     statusString  PkiFreeText     OPTIONAL,
		 *     failInfo      PkiFailureInfo  OPTIONAL  (BIT STRING)
		 * }
		 *
		 * PKIStatus:
		 *   granted                (0), -- you got exactly what you asked for
		 *   grantedWithMods        (1), -- you got something like what you asked for
		 *   rejection              (2), -- you don't get it, more information elsewhere in the message
		 *   waiting                (3), -- the request body part has not yet been processed, expect to hear more later
		 *   revocationWarning      (4), -- this message contains a warning that a revocation is imminent
		 *   revocationNotification (5), -- notification that a revocation has occurred
		 *   keyUpdateWarning       (6)  -- update already done for the oldCertId specified in CertReqMsg
		 *
		 * PkiFailureInfo:
		 *   badAlg           (0), -- unrecognized or unsupported Algorithm Identifier
		 *   badMessageCheck  (1), -- integrity check failed (e.g., signature did not verify)
		 *   badRequest       (2), -- transaction not permitted or supported
		 *   badTime          (3), -- messageTime was not sufficiently close to the system time, as defined by local policy
		 *   badCertId        (4), -- no certificate could be found matching the provided criteria
		 *   badDataFormat    (5), -- the data submitted has the wrong format
		 *   wrongAuthority   (6), -- the authority indicated in the request is different from the one creating the response token
		 *   incorrectData    (7), -- the requester's data is incorrect (for notary services)
		 *   missingTimeStamp (8), -- when the timestamp is missing but should be there (by policy)
		 *   badPOP           (9)  -- the proof-of-possession failed
		 *
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
			v.Add(m_status);
            v.AddOptional(m_statusString, m_failInfo);
			return new DerSequence(v);
		}
	}
}
