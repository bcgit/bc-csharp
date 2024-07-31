using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
	/**
	 * The Holder object.
	 * <p>
	 * For an v2 attribute certificate this is:
	 * 
	 * <pre>
	 *            Holder ::= SEQUENCE {
	 *                  baseCertificateID   [0] IssuerSerial OPTIONAL,
	 *                           -- the issuer and serial number of
	 *                           -- the holder's Public Key Certificate
	 *                  entityName          [1] GeneralNames OPTIONAL,
	 *                           -- the name of the claimant or role
	 *                  objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
	 *                           -- used to directly authenticate the holder,
	 *                           -- for example, an executable
	 *            }
	 * </pre>
	 * </p>
	 * <p>
	 * For an v1 attribute certificate this is:
	 * 
	 * <pre>
	 *         subject CHOICE {
	 *          baseCertificateID [0] EXPLICIT IssuerSerial,
	 *          -- associated with a Public Key Certificate
	 *          subjectName [1] EXPLICIT GeneralNames },
	 *          -- associated with a name
	 * </pre>
	 * </p>
	 */
	public class Holder
        : Asn1Encodable
    {
        public static Holder GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Holder holder)
                return holder;
			// TODO Remove v1 support (or move to separate class?)
            if (obj is Asn1TaggedObject taggedObject)
                return new Holder(taggedObject);
            return new Holder(Asn1Sequence.GetInstance(obj));
        }

        public static Holder GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Holder(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Holder GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Holder(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly IssuerSerial m_baseCertificateID;
        private readonly GeneralNames m_entityName;
        private readonly ObjectDigestInfo m_objectDigestInfo;
        private readonly int m_version;

        /**
		 * Constructor for a holder for an v1 attribute certificate.
		 * 
		 * @param tagObj The ASN.1 tagged holder object.
		 */
        public Holder(Asn1TaggedObject tagObj)
		{
			switch (tagObj.TagNo)
			{
			case 0:
				m_baseCertificateID = IssuerSerial.GetInstance(tagObj, true);
				break;
			case 1:
				m_entityName = GeneralNames.GetInstance(tagObj, true);
				break;
			default:
				throw new ArgumentException("unknown tag in Holder");
			}

			m_version = 0;
		}

		/**
		 * Constructor for a holder for an v2 attribute certificate. *
		 * 
		 * @param seq The ASN.1 sequence.
		 */
		private Holder(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_baseCertificateID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, IssuerSerial.GetTagged);
            m_entityName = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, GeneralNames.GetTagged);
            m_objectDigestInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, ObjectDigestInfo.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

			m_version = 1;
		}

		public Holder(IssuerSerial baseCertificateID)
			: this(baseCertificateID, 1)
		{
		}

        /**
		 * Constructs a holder from a IssuerSerial.
		 * @param baseCertificateID The IssuerSerial.
		 * @param version The version of the attribute certificate. 
		 */
        public Holder(IssuerSerial baseCertificateID, int version)
        {
            m_baseCertificateID = baseCertificateID;
            m_version = version;
        }

		/**
		 * Returns 1 for v2 attribute certificates or 0 for v1 attribute
		 * certificates. 
		 * @return The version of the attribute certificate.
		 */
		public int Version => m_version;

        /**
		 * Constructs a holder with an entityName for v2 attribute certificates or
		 * with a subjectName for v1 attribute certificates.
		 * 
		 * @param entityName The entity or subject name.
		 */
        public Holder(GeneralNames entityName)
            : this(entityName, 1)
        {
        }

        /**
		 * Constructs a holder with an entityName for v2 attribute certificates or
		 * with a subjectName for v1 attribute certificates.
		 * 
		 * @param entityName The entity or subject name.
		 * @param version The version of the attribute certificate. 
		 */
        public Holder(GeneralNames entityName, int version)
        {
            m_entityName = entityName;
            m_version = version;
        }

        /**
		 * Constructs a holder from an object digest info.
		 * 
		 * @param objectDigestInfo The object digest info object.
		 */
        public Holder(ObjectDigestInfo objectDigestInfo)
        {
            m_objectDigestInfo = objectDigestInfo;
            m_version = 1;
        }

		public IssuerSerial BaseCertificateID => m_baseCertificateID;

		/**
		 * Returns the entityName for an v2 attribute certificate or the subjectName
		 * for an v1 attribute certificate.
		 * 
		 * @return The entityname or subjectname.
		 */
		public GeneralNames EntityName => m_entityName;

		public ObjectDigestInfo ObjectDigestInfo => m_objectDigestInfo;

		/**
         * The Holder object.
         * <pre>
         *  Holder ::= Sequence {
         *        baseCertificateID   [0] IssuerSerial OPTIONAL,
         *                 -- the issuer and serial number of
         *                 -- the holder's Public Key Certificate
         *        entityName          [1] GeneralNames OPTIONAL,
         *                 -- the name of the claimant or role
         *        objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
         *                 -- used to directly authenticate the holder,
         *                 -- for example, an executable
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_version == 1)
            {
                Asn1EncodableVector v = new Asn1EncodableVector(3);
                v.AddOptionalTagged(false, 0, m_baseCertificateID);
                v.AddOptionalTagged(false, 1, m_entityName);
                v.AddOptionalTagged(false, 2, m_objectDigestInfo);
                return new DerSequence(v);
            }

            if (m_entityName != null)
                return new DerTaggedObject(true, 1, m_entityName);

            return new DerTaggedObject(true, 0, m_baseCertificateID);
        }
	}
}
