using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The POPODecKeyChallContent structure of RFC 4210, the proof-of-possession challenge.</summary>
    public class PopoDecKeyChallContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PopoDecKeyChallContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PopoDecKeyChallContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PopoDecKeyChallContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PopoDecKeyChallContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PopoDecKeyChallContent popoDecKeyChallContent)
                return popoDecKeyChallContent;
            return new PopoDecKeyChallContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PopoDecKeyChallContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PopoDecKeyChallContent"/>.</returns>
        public static PopoDecKeyChallContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PopoDecKeyChallContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PopoDecKeyChallContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PopoDecKeyChallContent"/>.</returns>
        public static PopoDecKeyChallContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PopoDecKeyChallContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private PopoDecKeyChallContent(Asn1Sequence seq)
        {
            m_content = seq;
        }

        public virtual Challenge[] ToChallengeArray() => m_content.MapElements(Challenge.GetInstance);

        /**
         * <pre>
         * PopoDecKeyChallContent ::= SEQUENCE OF Challenge
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
