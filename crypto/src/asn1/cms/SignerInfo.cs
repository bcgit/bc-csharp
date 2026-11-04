using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>
    /// Represents per-signer information within a SignedData
    /// </summary>
    /// <remarks>
    /// See RFC 5652 5.3.
    /// <code>
    /// SignerInfo ::= SEQUENCE {
    ///   version CMSVersion,
    ///   sid SignerIdentifier,
    ///   digestAlgorithm DigestAlgorithmIdentifier,
    ///   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
    ///   signatureAlgorithm SignatureAlgorithmIdentifier,
    ///   signature SignatureValue,
    ///   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
    ///
    /// SignerIdentifier ::= CHOICE {
    ///   issuerAndSerialNumber IssuerAndSerialNumber,
    ///   subjectKeyIdentifier [0] SubjectKeyIdentifier }
    ///
    /// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    ///
    /// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    ///
    /// Attribute ::= SEQUENCE {
    ///   attrType OBJECT IDENTIFIER,
    ///   attrValues SET OF AttributeValue }
    ///
    /// AttributeValue ::= ANY
    ///
    /// SignatureValue ::= OCTET STRING
    /// </code>
    /// </remarks>
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
            return new SignerInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="SignerInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignerInfo"/>.</returns>
        public static SignerInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignerInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SignerInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignerInfo"/>.</returns>
        public static SignerInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignerInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly SignerIdentifier m_sid;
        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly Asn1Set m_signedAttrs;
        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly Asn1OctetString m_signature;
        private readonly Asn1Set m_unsignedAttrs;

        private SignerInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 5 || count > 7)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_sid = Asn1Utilities.Read(seq, ref pos, SignerIdentifier.GetInstance);
            m_digestAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_signedAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1Set.GetTagged);
            m_signatureAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_signature = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_unsignedAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="SignerInfo"/>.</summary>
        /// <param name="sid">The sid.</param>
        /// <param name="digAlgorithm">The dig algorithm.</param>
        /// <param name="authenticatedAttributes">The authenticated attributes.</param>
        /// <param name="digEncryptionAlgorithm">The dig encryption algorithm.</param>
        /// <param name="encryptedDigest">The encrypted digest.</param>
        /// <param name="unauthenticatedAttributes">The unauthenticated attributes.</param>
        // TODO[api] Rename parameters according to fields
        public SignerInfo(SignerIdentifier sid, AlgorithmIdentifier digAlgorithm, Attributes authenticatedAttributes,
            AlgorithmIdentifier digEncryptionAlgorithm, Asn1OctetString encryptedDigest,
            Attributes unauthenticatedAttributes)
            : this(sid, digAlgorithm, authenticatedAttributes?.AttributeSet, digEncryptionAlgorithm,
                  encryptedDigest, unauthenticatedAttributes?.AttributeSet)
        {
        }

        /// <summary>Create a new <see cref="SignerInfo"/>.</summary>
        /// <param name="sid">The sid.</param>
        /// <param name="digAlgorithm">The dig algorithm.</param>
        /// <param name="authenticatedAttributes">The authenticated attributes.</param>
        /// <param name="digEncryptionAlgorithm">The dig encryption algorithm.</param>
        /// <param name="encryptedDigest">The encrypted digest.</param>
        /// <param name="unauthenticatedAttributes">The unauthenticated attributes.</param>
        // TODO[api] Rename parameters according to fields
        public SignerInfo(SignerIdentifier sid, AlgorithmIdentifier digAlgorithm, Asn1Set authenticatedAttributes,
            AlgorithmIdentifier digEncryptionAlgorithm, Asn1OctetString encryptedDigest,
            Asn1Set unauthenticatedAttributes)
        {
            m_sid = sid ?? throw new ArgumentNullException(nameof(sid));
            m_digestAlgorithm = digAlgorithm ?? throw new ArgumentNullException(nameof(digAlgorithm));
            m_signedAttrs = authenticatedAttributes;
            m_signatureAlgorithm = digEncryptionAlgorithm ??
                throw new ArgumentNullException(nameof(digEncryptionAlgorithm));
            m_signature = encryptedDigest ?? throw new ArgumentNullException(nameof(encryptedDigest));
            m_unsignedAttrs = unauthenticatedAttributes;
            m_version = sid.IsTagged ? DerInteger.Three : DerInteger.One;
        }

        /// <summary>Gets the authenticated attributes.</summary>
        [Obsolete("Use 'SignedAttrs' instead")]
        public Asn1Set AuthenticatedAttributes => m_signedAttrs;

        /// <summary>Gets the digest algorithm.</summary>
        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        /// <summary>Gets the digest encryption algorithm.</summary>
        [Obsolete("Use 'SignatureAlgorithm' instead")]
        public AlgorithmIdentifier DigestEncryptionAlgorithm => m_signatureAlgorithm;

        /// <summary>Gets the encrypted digest.</summary>
        [Obsolete("Use 'Signature' instead")]
        public Asn1OctetString EncryptedDigest => m_signature;

        /// <summary>Gets the signature.</summary>
        public Asn1OctetString Signature => m_signature;

        /// <summary>Gets the signature algorithm.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        /// <summary>Gets the signed attrs.</summary>
        public Asn1Set SignedAttrs => m_signedAttrs;

        /// <summary>Gets the signer ID.</summary>
        public SignerIdentifier SignerID => m_sid;

        /// <summary>Gets the unauthenticated attributes.</summary>
        [Obsolete("Use 'UnsignedAttrs' instead")]
        public Asn1Set UnauthenticatedAttributes => m_unsignedAttrs;

        /// <summary>Gets the unsigned attrs.</summary>
        public Asn1Set UnsignedAttrs => m_unsignedAttrs;

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            var v = new Asn1EncodableVector(7){ m_version, m_sid, m_digestAlgorithm };
            v.AddOptionalTagged(false, 0, m_signedAttrs);
            v.Add(m_signatureAlgorithm);
            v.Add(m_signature);
            v.AddOptionalTagged(false, 1, m_unsignedAttrs);
            return new DerSequence(v);
        }
    }
}
