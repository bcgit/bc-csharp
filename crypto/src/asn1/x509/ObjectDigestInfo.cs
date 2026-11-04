using System;

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

        /// <summary>Return an <see cref="ObjectDigestInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ObjectDigestInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ObjectDigestInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ObjectDigestInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ObjectDigestInfo objectDigestInfo)
                return objectDigestInfo;
            return new ObjectDigestInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ObjectDigestInfo"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ObjectDigestInfo"/>.</returns>
        public static ObjectDigestInfo GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new ObjectDigestInfo(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="ObjectDigestInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ObjectDigestInfo"/>.</returns>
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

            m_digestedObjectType = Asn1Utilities.Read(seq, ref pos, DerEnumerated.GetInstance);
            m_otherObjectTypeID = Asn1Utilities.ReadOptional(seq, ref pos, DerObjectIdentifier.GetOptional);
            m_digestAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_objectDigest = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

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
            m_digestedObjectType = DerEnumerated.ValueOf(digestedObjectType);

            if (digestedObjectType == OtherObjectDigest)
            {
                m_otherObjectTypeID = new DerObjectIdentifier(otherObjectTypeID);
            }

            m_digestAlgorithm = digestAlgorithm ?? throw new ArgumentNullException(nameof(digestAlgorithm));
            m_objectDigest = new DerBitString(objectDigest);
        }

        /// <summary>Gets the digested object type.</summary>
        public DerEnumerated DigestedObjectType => m_digestedObjectType;

        /// <summary>Gets the other object type ID.</summary>
        public DerObjectIdentifier OtherObjectTypeID => m_otherObjectTypeID;

        /// <summary>Gets the digest algorithm.</summary>
        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        /// <summary>Gets the object digest.</summary>
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
