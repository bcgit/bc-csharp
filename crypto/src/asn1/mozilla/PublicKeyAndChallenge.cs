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

        public static PublicKeyAndChallenge GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new PublicKeyAndChallenge(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static PublicKeyAndChallenge GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new PublicKeyAndChallenge(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly SubjectPublicKeyInfo m_spki;
        private readonly DerIA5String m_challenge;

        public PublicKeyAndChallenge(SubjectPublicKeyInfo spki, DerIA5String challenge)
        {
            m_spki = spki ?? throw new ArgumentNullException(nameof(spki));
            m_challenge = challenge ?? throw new ArgumentNullException(nameof(m_challenge));
        }

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

        public DerIA5String Challenge => m_challenge;

        public SubjectPublicKeyInfo Spki => m_spki;

        [Obsolete("Use 'Spki' instead")]
        public SubjectPublicKeyInfo SubjectPublicKeyInfo => m_spki;

        public override Asn1Object ToAsn1Object() => new DerSequence(m_spki, m_challenge);
    }
}
