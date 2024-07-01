using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tsp
{
    public class TstInfo
		: Asn1Encodable
	{
        public static TstInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TstInfo tstInfo)
                return tstInfo;
            return new TstInfo(Asn1Sequence.GetInstance(obj));
        }

        public static TstInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TstInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static TstInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TstInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
		private readonly DerObjectIdentifier m_policy;
		private readonly MessageImprint m_messageImprint;
		private readonly DerInteger m_serialNumber;
		private readonly Asn1GeneralizedTime m_genTime;
		private readonly Accuracy m_accuracy;
		private readonly DerBoolean m_ordering;
		private readonly DerInteger m_nonce;
		private readonly GeneralName m_tsa;
		private readonly X509Extensions m_extensions;

		private TstInfo(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 5 || count > 10)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_policy = DerObjectIdentifier.GetInstance(seq[pos++]);
            m_messageImprint = MessageImprint.GetInstance(seq[pos++]);
            m_serialNumber = DerInteger.GetInstance(seq[pos++]);
            m_genTime = Asn1GeneralizedTime.GetInstance(seq[pos++]);
            m_accuracy = Asn1Utilities.ReadOptional(seq, ref pos, Accuracy.GetOptional);
            m_ordering = Asn1Utilities.ReadOptional(seq, ref pos, DerBoolean.GetOptional) ?? DerBoolean.False;
            m_nonce = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);
            m_tsa = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, GeneralName.GetTagged); // CHOICE
            m_extensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        // TODO[api] 'tsaPolicyId' => 'policy'
        public TstInfo(DerObjectIdentifier tsaPolicyId, MessageImprint messageImprint, DerInteger serialNumber,
            Asn1GeneralizedTime genTime, Accuracy accuracy, DerBoolean ordering, DerInteger nonce, GeneralName tsa,
            X509Extensions extensions)
        {
            m_version = DerInteger.One;
            m_policy = tsaPolicyId ?? throw new ArgumentNullException(nameof(tsaPolicyId));
            m_messageImprint = messageImprint ?? throw new ArgumentNullException(nameof(messageImprint));
            m_serialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
            m_genTime = genTime ?? throw new ArgumentNullException(nameof(genTime));
            m_accuracy = accuracy;
            m_ordering = ordering ?? DerBoolean.False;
            m_nonce = nonce;
            m_tsa = tsa;
            m_extensions = extensions;
        }

        public DerInteger Version => m_version;

        public MessageImprint MessageImprint => m_messageImprint;

        public DerObjectIdentifier Policy => m_policy;

        public DerInteger SerialNumber => m_serialNumber;

        public Accuracy Accuracy => m_accuracy;

        public Asn1GeneralizedTime GenTime => m_genTime;

        public DerBoolean Ordering => m_ordering;

        public DerInteger Nonce => m_nonce;

        public GeneralName Tsa => m_tsa;

        public X509Extensions Extensions => m_extensions;

        /**
		 * <pre>
		 *
		 *     TstInfo ::= SEQUENCE  {
		 *        version                      INTEGER  { v1(1) },
		 *        policy                       TSAPolicyId,
		 *        messageImprint               MessageImprint,
		 *          -- MUST have the same value as the similar field in
		 *          -- TimeStampReq
		 *        serialNumber                 INTEGER,
		 *         -- Time-Stamping users MUST be ready to accommodate integers
		 *         -- up to 160 bits.
		 *        genTime                      GeneralizedTime,
		 *        accuracy                     Accuracy                 OPTIONAL,
		 *        ordering                     BOOLEAN             DEFAULT FALSE,
		 *        nonce                        INTEGER                  OPTIONAL,
		 *          -- MUST be present if the similar field was present
		 *          -- in TimeStampReq.  In that case it MUST have the same value.
		 *        tsa                          [0] GeneralName          OPTIONAL,
		 *        extensions                   [1] IMPLICIT Extensions   OPTIONAL  }
		 *
		 * </pre>
		 */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(10);
            v.Add(m_version, m_policy, m_messageImprint, m_serialNumber, m_genTime);
            v.AddOptional(m_accuracy);

            if (m_ordering.IsTrue)
            {
                v.Add(m_ordering);
            }

            v.AddOptional(m_nonce);
            v.AddOptionalTagged(true, 0, m_tsa); // CHOICE
            v.AddOptionalTagged(false, 1, m_extensions);
            return new DerSequence(v);
        }
    }
}
