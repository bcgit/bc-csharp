using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Tsp
{
	public class TimeStampReq
		: Asn1Encodable
	{
		private readonly DerInteger m_version;
		private readonly MessageImprint m_messageImprint;
		private readonly DerObjectIdentifier m_tsaPolicy;
		private readonly DerInteger m_nonce;
		private readonly DerBoolean m_certReq;
		private readonly X509Extensions m_extensions;

        public static TimeStampReq GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TimeStampReq timeStampReq)
                return timeStampReq;
            return new TimeStampReq(Asn1Sequence.GetInstance(obj));
        }

		public static TimeStampReq GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
		{
            return new TimeStampReq(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private TimeStampReq(Asn1Sequence seq)
		{
			int nbObjects = seq.Count;
			int seqStart = 0;

			// version
			m_version = DerInteger.GetInstance(seq[seqStart++]);

			// messageImprint
			m_messageImprint = MessageImprint.GetInstance(seq[seqStart++]);

			for (int opt = seqStart; opt < nbObjects; opt++)
			{
				// tsaPolicy
				if (seq[opt] is DerObjectIdentifier oid)
				{
					m_tsaPolicy = oid;
				}
				// nonce
				else if (seq[opt] is DerInteger derInteger)
				{
					m_nonce = derInteger;
				}
				// certReq
				else if (seq[opt] is DerBoolean derBoolean)
				{
					m_certReq = derBoolean;
				}
				// extensions
				else if (seq[opt] is Asn1TaggedObject tagged)
				{
					if (tagged.TagNo == 0)
					{
						m_extensions = X509Extensions.GetInstance(tagged, false);
					}
				}
			}
		}

        public TimeStampReq(MessageImprint messageImprint, DerObjectIdentifier tsaPolicy, DerInteger nonce,
            DerBoolean certReq, X509Extensions extensions)
        {
            // default
            m_version = new DerInteger(1);

            m_messageImprint = messageImprint;
            m_tsaPolicy = tsaPolicy;
            m_nonce = nonce;
            m_certReq = certReq;
            m_extensions = extensions;
        }

		public DerInteger Version => m_version;

		public MessageImprint MessageImprint => m_messageImprint;

		public DerObjectIdentifier ReqPolicy => m_tsaPolicy;

		public DerInteger Nonce => m_nonce;

		public DerBoolean CertReq => m_certReq;

		public X509Extensions Extensions => m_extensions;

		/**
		 * <pre>
		 * TimeStampReq ::= SEQUENCE  {
		 *  version                      INTEGER  { v1(1) },
		 *  messageImprint               MessageImprint,
		 *    --a hash algorithm OID and the hash value of the data to be
		 *    --time-stamped
		 *  reqPolicy             TSAPolicyId              OPTIONAL,
		 *  nonce                 INTEGER                  OPTIONAL,
		 *  certReq               BOOLEAN                  DEFAULT FALSE,
		 *  extensions            [0] IMPLICIT Extensions  OPTIONAL
		 * }
		 * </pre>
		 */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(6);
			v.Add(m_version, m_messageImprint);
            v.AddOptional(m_tsaPolicy, m_nonce);

            if (m_certReq != null && m_certReq.IsTrue)
            {
                v.Add(m_certReq);
            }

            v.AddOptionalTagged(false, 0, m_extensions);
            return new DerSequence(v);
        }
	}
}
