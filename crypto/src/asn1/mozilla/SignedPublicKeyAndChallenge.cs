using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Mozilla
{
    /// <summary>
    /// For parsing the SignedPublicKeyAndChallenge created by the KEYGEN tag included by Mozilla based browsers.
    /// </summary>
    /// <remarks>
    /// <code>
    /// SignedPublicKeyAndChallenge ::= SEQUENCE
    /// {
    ///     publicKeyAndChallenge   PublicKeyAndChallenge,
    ///     signatureAlgorithm      AlgorithmIdentifier,
    ///     signature               BIT STRING
    /// }
    /// </code>
    /// </remarks>
    public class SignedPublicKeyAndChallenge
        : Asn1Encodable
    {
        public static SignedPublicKeyAndChallenge GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SignedPublicKeyAndChallenge signedPublicKeyAndChallenge)
                return signedPublicKeyAndChallenge;
            return new SignedPublicKeyAndChallenge(Asn1Sequence.GetInstance(obj));
        }

        public static SignedPublicKeyAndChallenge GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new SignedPublicKeyAndChallenge(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly PublicKeyAndChallenge m_publicKeyAndChallenge;
        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly DerBitString m_signature;

        public SignedPublicKeyAndChallenge(PublicKeyAndChallenge publicKeyAndChallenge,
            AlgorithmIdentifier signatureAlgorithm, DerBitString signature)
        {
            m_publicKeyAndChallenge = publicKeyAndChallenge
                ?? throw new ArgumentNullException(nameof(publicKeyAndChallenge));
            m_signatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
            m_signature = signature ?? throw new ArgumentNullException(nameof(signature));
        }

        private SignedPublicKeyAndChallenge(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));
            if (seq.Count != 3)
                throw new ArgumentException($"Expected 3 elements, but found {seq.Count}", nameof(seq));

            m_publicKeyAndChallenge = PublicKeyAndChallenge.GetInstance(seq[0]);
            m_signatureAlgorithm = AlgorithmIdentifier.GetInstance(seq[1]);
            m_signature = DerBitString.GetInstance(seq[2]);
        }

        public PublicKeyAndChallenge PublicKeyAndChallenge => m_publicKeyAndChallenge;

        public DerBitString Signature => m_signature;

        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        public override Asn1Object ToAsn1Object() =>
            new DerSequence(m_publicKeyAndChallenge, m_signatureAlgorithm, m_signature);
    }
}
