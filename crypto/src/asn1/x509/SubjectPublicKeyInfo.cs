using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The object that contains the public key stored in a certficate.
     * <p>
     * The GetEncoded() method in the public keys in the JCE produces a DER
     * encoded one of these.</p>
     */
    public class SubjectPublicKeyInfo
        : Asn1Encodable
    {
        public static SubjectPublicKeyInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SubjectPublicKeyInfo subjectPublicKeyInfo)
                return subjectPublicKeyInfo;
            return new SubjectPublicKeyInfo(Asn1Sequence.GetInstance(obj));
        }

        public static SubjectPublicKeyInfo GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new SubjectPublicKeyInfo(Asn1Sequence.GetInstance(obj, explicitly));

        public static SubjectPublicKeyInfo GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is SubjectPublicKeyInfo subjectPublicKeyInfo)
                return subjectPublicKeyInfo;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new SubjectPublicKeyInfo(asn1Sequence);

            return null;
        }

        public static SubjectPublicKeyInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SubjectPublicKeyInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_algorithm;
        private readonly DerBitString m_publicKey;

        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, DerBitString publicKey)
        {
            m_algorithm = algID;
            m_publicKey = publicKey;
        }

        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, Asn1Encodable publicKey)
        {
            m_algorithm = algID;
            m_publicKey = new DerBitString(publicKey);
        }

        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, byte[] publicKey)
        {
            m_algorithm = algID;
            m_publicKey = new DerBitString(publicKey);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, ReadOnlySpan<byte> publicKey)
        {
            m_algorithm = algID;
            m_publicKey = new DerBitString(publicKey);
        }
#endif

        private SubjectPublicKeyInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_algorithm = AlgorithmIdentifier.GetInstance(seq[0]);
			m_publicKey = DerBitString.GetInstance(seq[1]);
		}

        public AlgorithmIdentifier Algorithm => m_algorithm;

        [Obsolete("Use 'Algorithm' instead")]
        public AlgorithmIdentifier AlgorithmID => m_algorithm;

        /**
         * for when the public key is an encoded object - if the bitstring
         * can't be decoded this routine raises an IOException.
         *
         * @exception IOException - if the bit string doesn't represent a Der
         * encoded object.
         */
        public Asn1Object ParsePublicKey() => Asn1Object.FromMemoryStream(m_publicKey.GetOctetMemoryStream());

        /// <summary>Return the public key as a raw bit string.</summary>
        public DerBitString PublicKey => m_publicKey;

        /// <summary>Return the public key as a raw bit string.</summary>
        [Obsolete("Use 'PublicKey' instead")]
        public DerBitString PublicKeyData => m_publicKey;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * SubjectPublicKeyInfo ::= Sequence {
         *                          algorithm AlgorithmIdentifier,
         *                          publicKey BIT STRING }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_algorithm, m_publicKey);
    }
}
