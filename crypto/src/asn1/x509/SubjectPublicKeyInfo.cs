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
        /// <summary>Return an <see cref="SubjectPublicKeyInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SubjectPublicKeyInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SubjectPublicKeyInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SubjectPublicKeyInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SubjectPublicKeyInfo subjectPublicKeyInfo)
                return subjectPublicKeyInfo;
            return new SubjectPublicKeyInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="SubjectPublicKeyInfo"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SubjectPublicKeyInfo"/>.</returns>
        public static SubjectPublicKeyInfo GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new SubjectPublicKeyInfo(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="SubjectPublicKeyInfo"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="SubjectPublicKeyInfo"/>, or null if <paramref name="element"/> is null.</returns>
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

        /// <summary>Return an <see cref="SubjectPublicKeyInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SubjectPublicKeyInfo"/>.</returns>
        public static SubjectPublicKeyInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SubjectPublicKeyInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_algorithm;
        private readonly DerBitString m_publicKey;

        /// <summary>Create a new <see cref="SubjectPublicKeyInfo"/>.</summary>
        /// <param name="algID">The alg ID.</param>
        /// <param name="publicKey">The public key.</param>
        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, DerBitString publicKey)
        {
            m_algorithm = algID;
            m_publicKey = publicKey;
        }

        /// <summary>Create a new <see cref="SubjectPublicKeyInfo"/>.</summary>
        /// <param name="algID">The alg ID.</param>
        /// <param name="publicKey">The public key.</param>
        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, Asn1Encodable publicKey)
        {
            m_algorithm = algID;
            m_publicKey = new DerBitString(publicKey);
        }

        /// <summary>Create a new <see cref="SubjectPublicKeyInfo"/>.</summary>
        /// <param name="algID">The alg ID.</param>
        /// <param name="publicKey">The public key.</param>
        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, byte[] publicKey)
        {
            m_algorithm = algID;
            m_publicKey = new DerBitString(publicKey);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Create a new <see cref="SubjectPublicKeyInfo"/>.</summary>
        /// <param name="algID">The alg ID.</param>
        /// <param name="publicKey">The public key.</param>
        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, ReadOnlySpan<byte> publicKey)
        {
            m_algorithm = algID;
            m_publicKey = new DerBitString(publicKey);
        }
#endif

        private SubjectPublicKeyInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_algorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_publicKey = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public AlgorithmIdentifier Algorithm => m_algorithm;

        /// <summary>Gets the algorithm ID.</summary>
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
