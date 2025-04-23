using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
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
        private readonly Asn1Set m_authenticatedAttributes;
        private readonly AlgorithmIdentifier m_digestEncryptionAlgorithm;
        private readonly Asn1OctetString m_encryptedDigest;
        private readonly Asn1Set m_unauthenticatedAttributes;

        private SignerInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 5 || count > 7)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_sid = SignerIdentifier.GetInstance(seq[pos++]);
            m_digestAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_authenticatedAttributes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false,
                Asn1Set.GetTagged);
            m_digestEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_encryptedDigest = Asn1OctetString.GetInstance(seq[pos++]);
            m_unauthenticatedAttributes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false,
                Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        // TODO[api] 'digAlgorithm' => 'digestAlgorithm', digEncryptionAlgorithm => 'digestEncryptionAlgorithm'
        public SignerInfo(SignerIdentifier sid, AlgorithmIdentifier digAlgorithm, Attributes authenticatedAttributes,
            AlgorithmIdentifier digEncryptionAlgorithm, Asn1OctetString encryptedDigest,
            Attributes unauthenticatedAttributes)
            : this(sid, digAlgorithm, Asn1Set.GetInstance(authenticatedAttributes), digEncryptionAlgorithm,
                  encryptedDigest, Asn1Set.GetInstance(unauthenticatedAttributes))
        {
        }

        // TODO[api] 'digAlgorithm' => 'digestAlgorithm', digEncryptionAlgorithm => 'digestEncryptionAlgorithm'
        public SignerInfo(SignerIdentifier sid, AlgorithmIdentifier digAlgorithm, Asn1Set authenticatedAttributes,
            AlgorithmIdentifier digEncryptionAlgorithm, Asn1OctetString encryptedDigest,
            Asn1Set unauthenticatedAttributes)
        {
            m_sid = sid ?? throw new ArgumentNullException(nameof(sid));
            m_digestAlgorithm = digAlgorithm ?? throw new ArgumentNullException(nameof(digAlgorithm));
            m_authenticatedAttributes = authenticatedAttributes;
            m_digestEncryptionAlgorithm = digEncryptionAlgorithm ??
                throw new ArgumentNullException(nameof(digEncryptionAlgorithm));
            m_encryptedDigest = encryptedDigest ?? throw new ArgumentNullException(nameof(encryptedDigest));
            m_unauthenticatedAttributes = unauthenticatedAttributes;
            m_version = sid.IsTagged ? DerInteger.Three : DerInteger.One;
        }

        public DerInteger Version => m_version;

        public SignerIdentifier SignerID => m_sid;

        public Asn1Set AuthenticatedAttributes => m_authenticatedAttributes;

        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        public Asn1OctetString EncryptedDigest => m_encryptedDigest;

        public AlgorithmIdentifier DigestEncryptionAlgorithm => m_digestEncryptionAlgorithm;

        public Asn1Set UnauthenticatedAttributes => m_unauthenticatedAttributes;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  SignerInfo ::= Sequence {
         *      version Version,
         *      sid SignerIdentifier,
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
            v.Add(m_version, m_sid, m_digestAlgorithm);
            v.AddOptionalTagged(false, 0, m_authenticatedAttributes);
            v.Add(m_digestEncryptionAlgorithm, m_encryptedDigest);
            v.AddOptionalTagged(false, 1, m_unauthenticatedAttributes);
            return new DerSequence(v);
        }
    }
}
