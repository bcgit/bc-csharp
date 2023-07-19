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

        public static SubjectPublicKeyInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new SubjectPublicKeyInfo(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private readonly AlgorithmIdentifier m_algID;
        private readonly DerBitString m_keyData;

        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, DerBitString publicKey)
        {
            m_algID = algID;
            m_keyData = publicKey;
        }

        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, Asn1Encodable publicKey)
        {
            m_algID = algID;
            m_keyData = new DerBitString(publicKey);
        }

        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, byte[] publicKey)
        {
            m_algID = algID;
            m_keyData = new DerBitString(publicKey);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public SubjectPublicKeyInfo(AlgorithmIdentifier algID, ReadOnlySpan<byte> publicKey)
        {
            m_algID = algID;
            m_keyData = new DerBitString(publicKey);
        }
#endif

        private SubjectPublicKeyInfo(Asn1Sequence seq)
        {
            if (seq.Count != 2)
				throw new ArgumentException("Bad sequence size: " + seq.Count, "seq");

            m_algID = AlgorithmIdentifier.GetInstance(seq[0]);
			m_keyData = DerBitString.GetInstance(seq[1]);
		}

        public AlgorithmIdentifier AlgorithmID => m_algID;

        /**
         * for when the public key is an encoded object - if the bitstring
         * can't be decoded this routine raises an IOException.
         *
         * @exception IOException - if the bit string doesn't represent a Der
         * encoded object.
         */
        public Asn1Object ParsePublicKey() => Asn1Object.FromByteArray(m_keyData.GetOctets());

        /**
         * for when the public key is raw bits...
         */
        public DerBitString PublicKeyData => m_keyData;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * SubjectPublicKeyInfo ::= Sequence {
         *                          algorithm AlgorithmIdentifier,
         *                          publicKey BIT STRING }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_algID, m_keyData);
    }
}
