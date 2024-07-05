using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
	 * The AccessDescription object.
	 * <pre>
	 * AccessDescription  ::=  SEQUENCE {
	 *       accessMethod          OBJECT IDENTIFIER,
	 *       accessLocation        GeneralName  }
	 * </pre>
	 */
    public class AccessDescription
		: Asn1Encodable
	{
		public readonly static DerObjectIdentifier IdADCAIssuers = new DerObjectIdentifier("1.3.6.1.5.5.7.48.2");
		public readonly static DerObjectIdentifier IdADOcsp = new DerObjectIdentifier("1.3.6.1.5.5.7.48.1");

        public static AccessDescription GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AccessDescription accessDescription)
                return accessDescription;
            return new AccessDescription(Asn1Sequence.GetInstance(obj));
        }

        public static AccessDescription GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AccessDescription(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static AccessDescription GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AccessDescription(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_accessMethod;
        private readonly GeneralName m_accessLocation;

        private AccessDescription(Asn1Sequence seq)
		{
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_accessMethod = DerObjectIdentifier.GetInstance(seq[0]);
			m_accessLocation = GeneralName.GetInstance(seq[1]);
		}

        /**
		 * create an AccessDescription with the oid and location provided.
		 */
		// TODO[api] Change parameter names
        public AccessDescription(DerObjectIdentifier oid, GeneralName location)
        {
            m_accessMethod = oid ?? throw new ArgumentNullException(nameof(oid));
            m_accessLocation = location ?? throw new ArgumentNullException(nameof(location));
        }

        public DerObjectIdentifier AccessMethod => m_accessMethod;

		public GeneralName AccessLocation => m_accessLocation;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_accessMethod, m_accessLocation);

		public override string ToString() => "AccessDescription: Oid(" + m_accessMethod.Id + ")";
	}
}
