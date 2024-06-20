using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class EncryptedPrivateKeyInfo
        : Asn1Encodable
    {
        public static EncryptedPrivateKeyInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptedPrivateKeyInfo encryptedPrivateKeyInfo)
                return encryptedPrivateKeyInfo;
            return new EncryptedPrivateKeyInfo(Asn1Sequence.GetInstance(obj));
        }

        public static EncryptedPrivateKeyInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new EncryptedPrivateKeyInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly AlgorithmIdentifier m_encryptionAlgorithm;
        private readonly Asn1OctetString m_encryptedData;

		private EncryptedPrivateKeyInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_encryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[0]);
            m_encryptedData = Asn1OctetString.GetInstance(seq[1]);
        }

        public EncryptedPrivateKeyInfo(AlgorithmIdentifier algId, byte[] encoding)
        {
            m_encryptionAlgorithm = algId ?? throw new ArgumentNullException(nameof(algId));
            m_encryptedData = new DerOctetString(encoding);
        }

        public AlgorithmIdentifier EncryptionAlgorithm => m_encryptionAlgorithm;

        public byte[] GetEncryptedData() => m_encryptedData.GetOctets();

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * EncryptedPrivateKeyInfo ::= Sequence {
         *      encryptionAlgorithm AlgorithmIdentifier {{KeyEncryptionAlgorithms}},
         *      encryptedData EncryptedData
         * }
         *
         * EncryptedData ::= OCTET STRING
         *
         * KeyEncryptionAlgorithms ALGORITHM-IDENTIFIER ::= {
         *          ... -- For local profiles
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_encryptionAlgorithm, m_encryptedData);
    }
}
