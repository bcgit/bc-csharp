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

        public static TstInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new TstInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger m_version;
		private readonly DerObjectIdentifier m_tsaPolicyID;
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
			var e = seq.GetEnumerator();

			// version
			e.MoveNext();
			m_version = DerInteger.GetInstance(e.Current);

			// tsaPolicy
			e.MoveNext();
			m_tsaPolicyID = DerObjectIdentifier.GetInstance(e.Current);

			// messageImprint
			e.MoveNext();
			m_messageImprint = MessageImprint.GetInstance(e.Current);

			// serialNumber
			e.MoveNext();
			m_serialNumber = DerInteger.GetInstance(e.Current);

			// genTime
			e.MoveNext();
			m_genTime = Asn1GeneralizedTime.GetInstance(e.Current);

			// default for ordering
			m_ordering = DerBoolean.False;

			while (e.MoveNext())
			{
				Asn1Object o = (Asn1Object) e.Current;

				if (o is Asn1TaggedObject tagged)
				{
					switch (tagged.TagNo)
					{
					case 0:
						m_tsa = GeneralName.GetInstance(tagged, true);
						break;
					case 1:
						m_extensions = X509Extensions.GetInstance(tagged, false);
						break;
					default:
						throw new ArgumentException("Unknown tag value " + tagged.TagNo);
					}
				}

				if (o is Asn1Sequence)
				{
					m_accuracy = Accuracy.GetInstance(o);
				}

				if (o is DerBoolean)
				{
					m_ordering = DerBoolean.GetInstance(o);
				}

				if (o is DerInteger)
				{
					m_nonce = DerInteger.GetInstance(o);
				}
			}
		}

        public TstInfo(DerObjectIdentifier tsaPolicyId, MessageImprint messageImprint, DerInteger serialNumber,
            Asn1GeneralizedTime genTime, Accuracy accuracy, DerBoolean ordering, DerInteger nonce, GeneralName tsa,
            X509Extensions extensions)
        {
            m_version = DerInteger.One;
            m_tsaPolicyID = tsaPolicyId;
            m_messageImprint = messageImprint;
            m_serialNumber = serialNumber;
            m_genTime = genTime;
            m_accuracy = accuracy;
            m_ordering = ordering;
            m_nonce = nonce;
            m_tsa = tsa;
            m_extensions = extensions;
        }

        public DerInteger Version => m_version;

        public MessageImprint MessageImprint => m_messageImprint;

        public DerObjectIdentifier Policy => m_tsaPolicyID;

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
            v.Add(m_version, m_tsaPolicyID, m_messageImprint, m_serialNumber, m_genTime);
            v.AddOptional(m_accuracy);

            if (m_ordering != null && m_ordering.IsTrue)
            {
                v.Add(m_ordering);
            }

            v.AddOptional(m_nonce);
            v.AddOptionalTagged(true, 0, m_tsa);
            v.AddOptionalTagged(false, 1, m_extensions);
            return new DerSequence(v);
        }
    }
}
