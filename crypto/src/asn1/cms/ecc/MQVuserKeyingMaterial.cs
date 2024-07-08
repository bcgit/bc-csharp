using System;

namespace Org.BouncyCastle.Asn1.Cms.Ecc
{
    public class MQVuserKeyingMaterial
		: Asn1Encodable
	{
        public static MQVuserKeyingMaterial GetInstance(object obj)
        {
			if (obj == null)
				return null;
			if (obj is MQVuserKeyingMaterial mqvUserKeyingMaterial)
				return mqvUserKeyingMaterial;
            return new MQVuserKeyingMaterial(Asn1Sequence.GetInstance(obj));
        }

        public static MQVuserKeyingMaterial GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new MQVuserKeyingMaterial(Asn1Sequence.GetInstance(obj, isExplicit));

        public static MQVuserKeyingMaterial GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MQVuserKeyingMaterial(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));


        private readonly OriginatorPublicKey m_ephemeralPublicKey;
		private readonly Asn1OctetString m_addedukm;

        public MQVuserKeyingMaterial(OriginatorPublicKey ephemeralPublicKey, Asn1OctetString addedukm)
        {
            m_ephemeralPublicKey = ephemeralPublicKey ?? throw new ArgumentNullException(nameof(ephemeralPublicKey));
			m_addedukm = addedukm;
		}

		private MQVuserKeyingMaterial(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_ephemeralPublicKey = OriginatorPublicKey.GetInstance(seq[pos++]);
			m_addedukm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1OctetString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        public OriginatorPublicKey EphemeralPublicKey => m_ephemeralPublicKey;

		public Asn1OctetString AddedUkm => m_addedukm;

        /**
		* Produce an object suitable for an Asn1OutputStream.
		* <pre>
		* MQVuserKeyingMaterial ::= SEQUENCE {
		*   ephemeralPublicKey OriginatorPublicKey,
		*   addedukm [0] EXPLICIT UserKeyingMaterial OPTIONAL  }
		* </pre>
		*/
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_ephemeralPublicKey);
            v.AddOptionalTagged(true, 0, m_addedukm);
            return new DerSequence(v);
        }
    }
}
