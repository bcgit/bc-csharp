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
        /// <summary>Return an <see cref="SignedPublicKeyAndChallenge"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SignedPublicKeyAndChallenge"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SignedPublicKeyAndChallenge"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SignedPublicKeyAndChallenge GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SignedPublicKeyAndChallenge signedPublicKeyAndChallenge)
                return signedPublicKeyAndChallenge;
            return new SignedPublicKeyAndChallenge(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="SignedPublicKeyAndChallenge"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignedPublicKeyAndChallenge"/>.</returns>
        public static SignedPublicKeyAndChallenge GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignedPublicKeyAndChallenge(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SignedPublicKeyAndChallenge"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignedPublicKeyAndChallenge"/>.</returns>
        public static SignedPublicKeyAndChallenge GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignedPublicKeyAndChallenge(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly PublicKeyAndChallenge m_publicKeyAndChallenge;
        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly DerBitString m_signature;

        /// <summary>Create a new <see cref="SignedPublicKeyAndChallenge"/>.</summary>
        /// <param name="publicKeyAndChallenge">The public key and challenge.</param>
        /// <param name="signatureAlgorithm">The signature algorithm.</param>
        /// <param name="signature">The signature.</param>
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

            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_publicKeyAndChallenge = Asn1Utilities.Read(seq, ref pos, PublicKeyAndChallenge.GetInstance);
            m_signatureAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_signature = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the public key and challenge.</summary>
        public PublicKeyAndChallenge PublicKeyAndChallenge => m_publicKeyAndChallenge;

        /// <summary>Gets the signature.</summary>
        public DerBitString Signature => m_signature;

        /// <summary>Gets the signature algorithm.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() =>
            new DerSequence(m_publicKeyAndChallenge, m_signatureAlgorithm, m_signature);
    }
}
