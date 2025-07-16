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
        public static SignerInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SignerInfo signerInfo)
                return signerInfo;
            return new SignerInfo(Asn1Sequence.GetInstance(obj));
        }

        public static SignerInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignerInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

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

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_sid = SignerIdentifier.GetInstance(seq[pos++]);
            m_digestAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_signedAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1Set.GetTagged);
            m_signatureAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_signature = Asn1OctetString.GetInstance(seq[pos++]);
            m_unsignedAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        // TODO[api] Rename parameters according to fields
        public SignerInfo(SignerIdentifier sid, AlgorithmIdentifier digAlgorithm, Attributes authenticatedAttributes,
            AlgorithmIdentifier digEncryptionAlgorithm, Asn1OctetString encryptedDigest,
            Attributes unauthenticatedAttributes)
            : this(sid, digAlgorithm, authenticatedAttributes?.AttributeSet, digEncryptionAlgorithm,
                  encryptedDigest, unauthenticatedAttributes?.AttributeSet)
        {
        }

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

        [Obsolete("Use 'SignedAttrs' instead")]
        public Asn1Set AuthenticatedAttributes => m_signedAttrs;

        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        [Obsolete("Use 'SignatureAlgorithm' instead")]
        public AlgorithmIdentifier DigestEncryptionAlgorithm => m_signatureAlgorithm;

        [Obsolete("Use 'Signature' instead")]
        public Asn1OctetString EncryptedDigest => m_signature;

        public Asn1OctetString Signature => m_signature;

        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        public Asn1Set SignedAttrs => m_signedAttrs;

        public SignerIdentifier SignerID => m_sid;

        [Obsolete("Use 'UnsignedAttrs' instead")]
        public Asn1Set UnauthenticatedAttributes => m_unsignedAttrs;

        public Asn1Set UnsignedAttrs => m_unsignedAttrs;

        public DerInteger Version => m_version;

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
