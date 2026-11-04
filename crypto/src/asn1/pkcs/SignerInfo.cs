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
        /// <summary>Return an <see cref="SignerInfo"/> from the given object.</summary>
        /// <param name="obj">An <see cref="SignerInfo"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="SignerInfo"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="SignerInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignerInfo"/>.</returns>
        public static SignerInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SignerInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="SignerInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignerInfo"/>.</returns>
        public static SignerInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SignerInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_version;
        private readonly IssuerAndSerialNumber m_issuerAndSerialNumber;
        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly Asn1Set m_authenticatedAttributes;
        private readonly AlgorithmIdentifier m_digestEncryptionAlgorithm;
        private readonly Asn1OctetString m_encryptedDigest;
        private readonly Asn1Set m_unauthenticatedAttributes;

        /// <summary>Create a new <see cref="SignerInfo"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public SignerInfo(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 5 || count > 7)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_issuerAndSerialNumber = Asn1Utilities.Read(seq, ref pos, IssuerAndSerialNumber.GetInstance);
            m_digestAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_authenticatedAttributes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false,
                Asn1Set.GetTagged);
            m_digestEncryptionAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_encryptedDigest = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_unauthenticatedAttributes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false,
                Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="SignerInfo"/>.</summary>
        /// <param name="version">The version.</param>
        /// <param name="issuerAndSerialNumber">The issuer and serial number.</param>
        /// <param name="digAlgorithm">The dig algorithm.</param>
        /// <param name="authenticatedAttributes">The authenticated attributes.</param>
        /// <param name="digEncryptionAlgorithm">The dig encryption algorithm.</param>
        /// <param name="encryptedDigest">The encrypted digest.</param>
        /// <param name="unauthenticatedAttributes">The unauthenticated attributes.</param>
        // TODO[api] 'digAlgorithm' => 'digestAlgorithm', digEncryptionAlgorithm => 'digestEncryptionAlgorithm'
        public SignerInfo(DerInteger version, IssuerAndSerialNumber issuerAndSerialNumber,
            AlgorithmIdentifier digAlgorithm, Asn1Set authenticatedAttributes,
            AlgorithmIdentifier digEncryptionAlgorithm, Asn1OctetString encryptedDigest,
            Asn1Set unauthenticatedAttributes)
        {
            m_version = version ?? throw new ArgumentNullException(nameof(version));
            m_issuerAndSerialNumber = issuerAndSerialNumber ??
                throw new ArgumentNullException(nameof(issuerAndSerialNumber));
            m_digestAlgorithm = digAlgorithm ?? throw new ArgumentNullException(nameof(digAlgorithm));
            m_authenticatedAttributes = authenticatedAttributes;
            m_digestEncryptionAlgorithm = digEncryptionAlgorithm ??
                throw new ArgumentNullException(nameof(digEncryptionAlgorithm));
            m_encryptedDigest = encryptedDigest ?? throw new ArgumentNullException(nameof(encryptedDigest));
            m_unauthenticatedAttributes = unauthenticatedAttributes;
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <summary>Gets the issuer and serial number.</summary>
        public IssuerAndSerialNumber IssuerAndSerialNumber => m_issuerAndSerialNumber;

        /// <summary>Gets the authenticated attributes.</summary>
        public Asn1Set AuthenticatedAttributes => m_authenticatedAttributes;

        /// <summary>Gets the digest algorithm.</summary>
        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        /// <summary>Gets the encrypted digest.</summary>
        public Asn1OctetString EncryptedDigest => m_encryptedDigest;

        /// <summary>Gets the digest encryption algorithm.</summary>
        public AlgorithmIdentifier DigestEncryptionAlgorithm => m_digestEncryptionAlgorithm;

        /// <summary>Gets the unauthenticated attributes.</summary>
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
            v.Add(m_version, m_issuerAndSerialNumber, m_digestAlgorithm);
            v.AddOptionalTagged(false, 0, m_authenticatedAttributes);
            v.Add(m_digestEncryptionAlgorithm, m_encryptedDigest);
            v.AddOptionalTagged(false, 1, m_unauthenticatedAttributes);
            return new DerSequence(v);
        }
    }
}
