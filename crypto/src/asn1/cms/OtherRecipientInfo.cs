using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The OtherRecipientInfo structure of RFC 5652, for recipient types defined elsewhere.</summary>
    public class OtherRecipientInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OtherRecipientInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OtherRecipientInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OtherRecipientInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OtherRecipientInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherRecipientInfo otherRecipientInfo)
                return otherRecipientInfo;
            return new OtherRecipientInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OtherRecipientInfo"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherRecipientInfo"/>.</returns>
        public static OtherRecipientInfo GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new OtherRecipientInfo(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="OtherRecipientInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherRecipientInfo"/>.</returns>
        public static OtherRecipientInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherRecipientInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_oriType;
        private readonly Asn1Encodable m_oriValue;

        /// <summary>Create a new <see cref="OtherRecipientInfo"/>.</summary>
        /// <param name="oriType">The ori type.</param>
        /// <param name="oriValue">The ori value.</param>
        public OtherRecipientInfo(DerObjectIdentifier oriType, Asn1Encodable oriValue)
        {
            m_oriType = oriType ?? throw new ArgumentNullException(nameof(oriType));
            m_oriValue = oriValue ?? throw new ArgumentNullException(nameof(oriValue));
        }

        private OtherRecipientInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_oriType = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_oriValue = Asn1Utilities.Read(seq, ref pos, element => element);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the ori type.</summary>
        public virtual DerObjectIdentifier OriType => m_oriType;

        /// <summary>Gets the ori value.</summary>
        public virtual Asn1Encodable OriValue => m_oriValue;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OtherRecipientInfo ::= Sequence {
         *    oriType OBJECT IDENTIFIER,
         *    oriValue ANY DEFINED BY oriType }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_oriType, m_oriValue);
    }
}
