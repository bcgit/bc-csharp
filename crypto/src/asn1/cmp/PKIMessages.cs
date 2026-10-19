using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The PKIMessages structure of RFC 4210: a sequence of PKI messages.</summary>
    public class PkiMessages
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PkiMessages"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PkiMessages"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PkiMessages"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PkiMessages GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiMessages pkiMessages)
                return pkiMessages;
            return new PkiMessages(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PkiMessages"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiMessages"/>.</returns>
        public static PkiMessages GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiMessages(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PkiMessages"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiMessages"/>.</returns>
        public static PkiMessages GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiMessages(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private Asn1Sequence m_content;

        internal PkiMessages(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            m_content = seq;
        }

        internal PkiMessages(PkiMessages other)
        {
            m_content = other.m_content;
        }

        /// <summary>Create a new <see cref="PkiMessages"/>.</summary>
        /// <param name="msgs">The msgs.</param>
        public PkiMessages(params PkiMessage[] msgs)
        {
            m_content = new DerSequence(msgs);
        }

        /// <summary>Return the messages as an array.</summary>
        /// <returns>A new array holding the messages.</returns>
        public virtual PkiMessage[] ToPkiMessageArray() => m_content.MapElements(PkiMessage.GetInstance);

        /**
         * <pre>
         * PkiMessages ::= SEQUENCE SIZE (1..MAX) OF PkiMessage
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
