using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Mozilla
{
    /// <summary>
    /// For parsing the PublicKeyAndChallenge created by the KEYGEN tag included by Mozilla based browsers.
    /// </summary>
    /// <remarks>
    /// <code>
    /// PublicKeyAndChallenge ::= SEQUENCE
    /// {
    ///     spki        SubjectPublicKeyInfo,
    ///     challenge   IA5STRING
    /// }
    /// </code>
    /// </remarks>
    public class PublicKeyAndChallenge
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PublicKeyAndChallenge"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PublicKeyAndChallenge"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PublicKeyAndChallenge"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PublicKeyAndChallenge GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PublicKeyAndChallenge publicKeyAndChallenge)
                return publicKeyAndChallenge;
#pragma warning disable CS0618 // Type or member is obsolete
            return new PublicKeyAndChallenge(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="PublicKeyAndChallenge"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PublicKeyAndChallenge"/>.</returns>
        public static PublicKeyAndChallenge GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new PublicKeyAndChallenge(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="PublicKeyAndChallenge"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PublicKeyAndChallenge"/>.</returns>
        public static PublicKeyAndChallenge GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new PublicKeyAndChallenge(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly SubjectPublicKeyInfo m_spki;
        private readonly DerIA5String m_challenge;

        /// <summary>Create a new <see cref="PublicKeyAndChallenge"/>.</summary>
        /// <param name="spki">The spki.</param>
        /// <param name="challenge">The challenge.</param>
        public PublicKeyAndChallenge(SubjectPublicKeyInfo spki, DerIA5String challenge)
        {
            m_spki = spki ?? throw new ArgumentNullException(nameof(spki));
            m_challenge = challenge ?? throw new ArgumentNullException(nameof(m_challenge));
        }

        /// <summary>Create a new <see cref="PublicKeyAndChallenge"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public PublicKeyAndChallenge(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_spki = Asn1Utilities.Read(seq, ref pos, SubjectPublicKeyInfo.GetInstance);
            m_challenge = Asn1Utilities.Read(seq, ref pos, DerIA5String.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the challenge.</summary>
        public DerIA5String Challenge => m_challenge;

        /// <summary>Gets the spki.</summary>
        public SubjectPublicKeyInfo Spki => m_spki;

        /// <summary>Gets the subject public key info.</summary>
        [Obsolete("Use 'Spki' instead")]
        public SubjectPublicKeyInfo SubjectPublicKeyInfo => m_spki;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_spki, m_challenge);
    }
}
