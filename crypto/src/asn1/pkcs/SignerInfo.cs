using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /**
     * a Pkcs#7 signer info object.
     */
    public class SignerInfo
        : Asn1Encodable
    {
        public static SignerInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SignerInfo signerInfo)
                return signerInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new SignerInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static SignerInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SignerInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_version;
        private readonly IssuerAndSerialNumber m_issuerAndSerialNumber;
        private readonly AlgorithmIdentifier m_digAlgorithm;
        private readonly Asn1Set m_authenticatedAttributes;
        private readonly AlgorithmIdentifier m_digEncryptionAlgorithm;
        private readonly Asn1OctetString m_encryptedDigest;
        private readonly Asn1Set m_unauthenticatedAttributes;

        [Obsolete("Use 'GetInstance' instead")]
        public SignerInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 5 || count > 7)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_issuerAndSerialNumber = IssuerAndSerialNumber.GetInstance(seq[pos++]);
            m_digAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_authenticatedAttributes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1Set.GetTagged);
            m_digEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_encryptedDigest = Asn1OctetString.GetInstance(seq[pos++]);
            m_unauthenticatedAttributes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public SignerInfo(
            DerInteger version,
            IssuerAndSerialNumber issuerAndSerialNumber,
            AlgorithmIdentifier digAlgorithm,
            Asn1Set authenticatedAttributes,
            AlgorithmIdentifier digEncryptionAlgorithm,
            Asn1OctetString encryptedDigest,
            Asn1Set unauthenticatedAttributes)
        {
            m_version = version ?? throw new ArgumentNullException(nameof(version));
            m_issuerAndSerialNumber = issuerAndSerialNumber ?? throw new ArgumentNullException(nameof(issuerAndSerialNumber));
            m_digAlgorithm = digAlgorithm ?? throw new ArgumentNullException(nameof(digAlgorithm));
            m_authenticatedAttributes = authenticatedAttributes;
            m_digEncryptionAlgorithm = digEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(digEncryptionAlgorithm));
            m_encryptedDigest = encryptedDigest ?? throw new ArgumentNullException(nameof(encryptedDigest));
            m_unauthenticatedAttributes = unauthenticatedAttributes;
        }

        public DerInteger Version => m_version;

		public IssuerAndSerialNumber IssuerAndSerialNumber => m_issuerAndSerialNumber;

        public Asn1Set AuthenticatedAttributes => m_authenticatedAttributes;

        public AlgorithmIdentifier DigestAlgorithm => m_digAlgorithm;

		public Asn1OctetString EncryptedDigest => m_encryptedDigest;

		public AlgorithmIdentifier DigestEncryptionAlgorithm => m_digEncryptionAlgorithm;

		public Asn1Set UnauthenticatedAttributes => m_unauthenticatedAttributes;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  SignerInfo ::= Sequence {
         *      version Version,
         *      issuerAndSerialNumber IssuerAndSerialNumber,
         *      digestAlgorithm DigestAlgorithmIdentifier,
         *      authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
         *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
         *      encryptedDigest EncryptedDigest,
         *      unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
         *  }
         *
         *  EncryptedDigest ::= OCTET STRING
         *
         *  DigestAlgorithmIdentifier ::= AlgorithmIdentifier
         *
         *  DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(7);
            v.Add(m_version, m_issuerAndSerialNumber, m_digAlgorithm);
            v.AddOptionalTagged(false, 0, m_authenticatedAttributes);
            v.Add(m_digEncryptionAlgorithm, m_encryptedDigest);
            v.AddOptionalTagged(false, 1, m_unauthenticatedAttributes);
            return new DerSequence(v);
        }
    }
}
