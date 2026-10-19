using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * <code>UserNotice</code> class, used in
     * <code>CertificatePolicies</code> X509 extensions (in policy
     * qualifiers).
     * <pre>
     * UserNotice ::= Sequence {
     *      noticeRef        NoticeReference OPTIONAL,
     *      explicitText     DisplayText OPTIONAL}
     *
     * </pre>
     *
     * @see PolicyQualifierId
     * @see PolicyInformation
     */
    public class UserNotice
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="UserNotice"/> from the given object.</summary>
        /// <param name="obj">An <see cref="UserNotice"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="UserNotice"/>, or null if <paramref name="obj"/> is null.</returns>
        public static UserNotice GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is UserNotice userNotice)
                return userNotice;
            return new UserNotice(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="UserNotice"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="UserNotice"/>.</returns>
        public static UserNotice GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new UserNotice(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="UserNotice"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="UserNotice"/>.</returns>
        public static UserNotice GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new UserNotice(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly NoticeReference m_noticeRef;
        private readonly DisplayText m_explicitText;

        private UserNotice(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_noticeRef = Asn1Utilities.ReadOptional(seq, ref pos, NoticeReference.GetOptional);
            m_explicitText = Asn1Utilities.ReadOptional(seq, ref pos, DisplayText.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /**
         * Creates a new <code>UserNotice</code> instance.
         *
         * @param noticeRef a <code>NoticeReference</code> value
         * @param explicitText a <code>DisplayText</code> value
         */
        public UserNotice(NoticeReference noticeRef, DisplayText explicitText)
        {
            m_noticeRef = noticeRef;
            m_explicitText = explicitText;
        }

        /**
         * Creates a new <code>UserNotice</code> instance.
         *
         * @param noticeRef a <code>NoticeReference</code> value
         * @param str the explicitText field as a string.
         */
        public UserNotice(NoticeReference noticeRef, string str)
            : this(noticeRef, new DisplayText(str))
        {
        }

        public virtual NoticeReference NoticeRef => m_noticeRef;

        /// <summary>Gets the explicit text.</summary>
        public virtual DisplayText ExplicitText => m_explicitText;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptional(m_noticeRef, m_explicitText);
            return new DerSequence(v);
        }
    }
}
