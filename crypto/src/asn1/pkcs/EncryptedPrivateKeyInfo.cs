using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The EncryptedPrivateKeyInfo structure of PKCS#8.</summary>
    public class EncryptedPrivateKeyInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="EncryptedPrivateKeyInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="EncryptedPrivateKeyInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="EncryptedPrivateKeyInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static EncryptedPrivateKeyInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptedPrivateKeyInfo encryptedPrivateKeyInfo)
                return encryptedPrivateKeyInfo;
            return new EncryptedPrivateKeyInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="EncryptedPrivateKeyInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptedPrivateKeyInfo"/>.</returns>
        public static EncryptedPrivateKeyInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptedPrivateKeyInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="EncryptedPrivateKeyInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptedPrivateKeyInfo"/>.</returns>
        public static EncryptedPrivateKeyInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptedPrivateKeyInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_encryptionAlgorithm;
        private readonly Asn1OctetString m_encryptedData;

        private EncryptedPrivateKeyInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_encryptionAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_encryptedData = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="EncryptedPrivateKeyInfo"/>.</summary>
        /// <param name="algId">The alg id.</param>
        /// <param name="encoding">The encoding.</param>
        // TODO[api] Change parameter names to match fields
        public EncryptedPrivateKeyInfo(AlgorithmIdentifier algId, byte[] encoding)
        {
            m_encryptionAlgorithm = algId ?? throw new ArgumentNullException(nameof(algId));
            m_encryptedData = DerOctetString.FromContents(encoding);
        }

        /// <summary>Create a new <see cref="EncryptedPrivateKeyInfo"/>.</summary>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <param name="encryptedData">The encrypted data.</param>
        public EncryptedPrivateKeyInfo(AlgorithmIdentifier encryptionAlgorithm, Asn1OctetString encryptedData)
        {
            m_encryptionAlgorithm = encryptionAlgorithm ?? throw new ArgumentNullException(nameof(encryptionAlgorithm));
            m_encryptedData = encryptedData ?? throw new ArgumentNullException(nameof(encryptedData));
        }

        /// <summary>Gets the encrypted data.</summary>
        public Asn1OctetString EncryptedData => m_encryptedData;

        /// <summary>Gets the encryption algorithm.</summary>
        public AlgorithmIdentifier EncryptionAlgorithm => m_encryptionAlgorithm;

        /// <summary>Return the encrypted data.</summary>
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
