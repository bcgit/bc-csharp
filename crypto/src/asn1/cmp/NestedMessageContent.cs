using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * NestedMessageContent ::= PKIMessages
     */
    public class NestedMessageContent
        : PkiMessages
    {
        /// <summary>Return an <see cref="NestedMessageContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="NestedMessageContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="NestedMessageContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static new NestedMessageContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is NestedMessageContent nestedMessageContent)
                return nestedMessageContent;
            if (obj is PkiMessages pkiMessages)
                return new NestedMessageContent(pkiMessages);
#pragma warning disable CS0618 // Type or member is obsolete
            return new NestedMessageContent(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="NestedMessageContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="NestedMessageContent"/>.</returns>
        public static new NestedMessageContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new NestedMessageContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="NestedMessageContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="NestedMessageContent"/>.</returns>
        public static new NestedMessageContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new NestedMessageContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Create a new <see cref="NestedMessageContent"/>.</summary>
        /// <param name="msg">The message.</param>
        public NestedMessageContent(PkiMessage msg)
            : base(msg)
        {
        }

        /// <summary>Create a new <see cref="NestedMessageContent"/>.</summary>
        /// <param name="msgs">The msgs.</param>
        public NestedMessageContent(PkiMessage[] msgs)
            : base(msgs)
        {
        }

        /// <summary>Create a new <see cref="NestedMessageContent"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public NestedMessageContent(Asn1Sequence seq)
            : base(seq)
        {
        }

        internal NestedMessageContent(PkiMessages other)
            : base(other)
        {
        }
    }
}
