using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
	/**
	 * ObjectDigestInfo ASN.1 structure used in v2 attribute certificates.
	 * 
	 * <pre>
	 *  
	 *    ObjectDigestInfo ::= SEQUENCE {
	 *         digestedObjectType  ENUMERATED {
	 *                 publicKey            (0),
	 *                 publicKeyCert        (1),
	 *                 otherObjectTypes     (2) },
	 *                         -- otherObjectTypes MUST NOT
	 *                         -- be used in this profile
	 *         otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
	 *         digestAlgorithm     AlgorithmIdentifier,
	 *         objectDigest        BIT STRING
	 *    }
	 *   
	 * </pre>
	 * 
	 */
	public class ObjectDigestInfo
        : Asn1Encodable
    {
		/**
		 * The public key is hashed.
		 */
		public const int PublicKey = 0;

		/**
		 * The public key certificate is hashed.
		 */
		public const int PublicKeyCert = 1;

		/**
		 * An other object is hashed.
		 */
		public const int OtherObjectDigest = 2;

        public static ObjectDigestInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ObjectDigestInfo objectDigestInfo)
                return objectDigestInfo;
            return new ObjectDigestInfo(Asn1Sequence.GetInstance(obj));
        }

        public static ObjectDigestInfo GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new ObjectDigestInfo(Asn1Sequence.GetInstance(obj, isExplicit));

        public static ObjectDigestInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ObjectDigestInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerEnumerated m_digestedObjectType;
        private readonly DerObjectIdentifier m_otherObjectTypeID;
        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly DerBitString m_objectDigest;

        private ObjectDigestInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_digestedObjectType = DerEnumerated.GetInstance(seq[pos++]);
			m_otherObjectTypeID = Asn1Utilities.ReadOptional(seq, ref pos, DerObjectIdentifier.GetOptional);
			m_digestAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
			m_objectDigest = DerBitString.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /**
		 * Constructor from given details.
		 * <p>
		 * If <code>digestedObjectType</code> is not {@link #publicKeyCert} or
		 * {@link #publicKey} <code>otherObjectTypeID</code> must be given,
		 * otherwise it is ignored.</p>
		 * 
		 * @param digestedObjectType The digest object type.
		 * @param otherObjectTypeID The object type ID for
		 *            <code>otherObjectDigest</code>.
		 * @param digestAlgorithm The algorithm identifier for the hash.
		 * @param objectDigest The hash value.
		 */
        public ObjectDigestInfo(int digestedObjectType, string otherObjectTypeID,
			AlgorithmIdentifier digestAlgorithm, byte[] objectDigest)
        {
            m_digestedObjectType = new DerEnumerated(digestedObjectType);

			if (digestedObjectType == OtherObjectDigest)
			{
				m_otherObjectTypeID = new DerObjectIdentifier(otherObjectTypeID);
			}

			m_digestAlgorithm = digestAlgorithm ?? throw new ArgumentNullException(nameof(digestAlgorithm));
			m_objectDigest = new DerBitString(objectDigest);
		}

		public DerEnumerated DigestedObjectType => m_digestedObjectType;

		public DerObjectIdentifier OtherObjectTypeID => m_otherObjectTypeID;

		public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

		public DerBitString ObjectDigest => m_objectDigest;

		/**
		 * Produce an object suitable for an Asn1OutputStream.
		 * 
		 * <pre>
		 *  
		 *    ObjectDigestInfo ::= SEQUENCE {
		 *         digestedObjectType  ENUMERATED {
		 *                 publicKey            (0),
		 *                 publicKeyCert        (1),
		 *                 otherObjectTypes     (2) },
		 *                         -- otherObjectTypes MUST NOT
		 *                         -- be used in this profile
		 *         otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
		 *         digestAlgorithm     AlgorithmIdentifier,
		 *         objectDigest        BIT STRING
		 *    }
		 *   
		 * </pre>
		 */
        public override Asn1Object ToAsn1Object()
        {
			return m_otherObjectTypeID == null
				?  new DerSequence(m_digestedObjectType, m_digestAlgorithm, m_objectDigest)
				:  new DerSequence(m_digestedObjectType, m_otherObjectTypeID, m_digestAlgorithm, m_objectDigest);
        }
    }
}
