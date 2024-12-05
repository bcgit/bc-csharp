using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tsp
{
    public class TimeStampReq
		: Asn1Encodable
	{
		private readonly DerInteger m_version;
		private readonly MessageImprint m_messageImprint;
		private readonly DerObjectIdentifier m_reqPolicy;
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

		public static TimeStampReq GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampReq(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static TimeStampReq GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampReq(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private TimeStampReq(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 6)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_version = DerInteger.GetInstance(seq[pos++]);
			m_messageImprint = MessageImprint.GetInstance(seq[pos++]);
			m_reqPolicy = Asn1Utilities.ReadOptional(seq, ref pos, DerObjectIdentifier.GetOptional);
            m_nonce = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);
            m_certReq = Asn1Utilities.ReadOptional(seq, ref pos, DerBoolean.GetOptional) ?? DerBoolean.False;
			m_extensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

		// TODO[api] 'tsaPolicy' => 'reqPolicy'
        public TimeStampReq(MessageImprint messageImprint, DerObjectIdentifier tsaPolicy, DerInteger nonce,
            DerBoolean certReq, X509Extensions extensions)
        {
            // default
            m_version = DerInteger.One;

            m_messageImprint = messageImprint ?? throw new ArgumentNullException(nameof(messageImprint));
            m_reqPolicy = tsaPolicy;
            m_nonce = nonce;
            m_certReq = certReq ?? DerBoolean.False;
            m_extensions = extensions;
        }

		public DerInteger Version => m_version;

		public MessageImprint MessageImprint => m_messageImprint;

		public DerObjectIdentifier ReqPolicy => m_reqPolicy;

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
            v.AddOptional(m_reqPolicy, m_nonce);

            if (m_certReq.IsTrue)
            {
                v.Add(m_certReq);
            }

            v.AddOptionalTagged(false, 0, m_extensions);
            return new DerSequence(v);
        }
	}
}
