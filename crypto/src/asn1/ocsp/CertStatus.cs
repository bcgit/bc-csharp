using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The CertStatus choice of RFC 6960: good, revoked or unknown.</summary>
    public class CertStatus
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="CertStatus"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CertStatus"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CertStatus"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertStatus GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="CertStatus"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertStatus"/>.</returns>
        public static CertStatus GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="CertStatus"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="CertStatus"/>, or null if <paramref name="element"/> is null.</returns>
        public static CertStatus GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CertStatus certStatus)
                return certStatus;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new CertStatus(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        /// <summary>Return an <see cref="CertStatus"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertStatus"/>.</returns>
        public static CertStatus GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static Asn1Encodable GetOptionalBaseObject(Asn1TaggedObject taggedObject)
        {
            if (taggedObject.HasContextTag())
            {
                switch (taggedObject.TagNo)
                {
                case 0:
                    return Asn1Null.GetTagged(taggedObject, false);
                case 1:
                    return RevokedInfo.GetTagged(taggedObject, false);
                case 2:
                    return Asn1Null.GetTagged(taggedObject, false);
                }
            }

            return null;
        }

        private readonly int m_tagNo;
        private readonly Asn1Encodable m_value;

        /**
         * create a CertStatus object with a tag of zero.
         */
        public CertStatus()
        {
            m_tagNo = 0;
            m_value = DerNull.Instance;
        }

        /// <summary>Create a new <see cref="CertStatus"/>.</summary>
        /// <param name="info">The info.</param>
        public CertStatus(RevokedInfo info)
        {
            m_tagNo = 1;
            m_value = info ?? throw new ArgumentNullException(nameof(info));
        }

        /// <summary>Create a new <see cref="CertStatus"/>.</summary>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="value">The value.</param>
        public CertStatus(int tagNo, Asn1Encodable value)
        {
            m_tagNo = tagNo;
            m_value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>Create a new <see cref="CertStatus"/>.</summary>
        /// <param name="choice">The choice.</param>
        public CertStatus(Asn1TaggedObject choice)
        {
            m_tagNo = choice.TagNo;
            m_value = GetOptionalBaseObject(choice) ??
                throw new ArgumentException("unknown tag: " + Asn1Utilities.GetTagText(choice), nameof(choice));
        }

        /// <summary>Gets the tag no.</summary>
        public int TagNo => m_tagNo;

        /// <summary>Gets the status.</summary>
        public Asn1Encodable Status => m_value;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  CertStatus ::= CHOICE {
         *                  good        [0]     IMPLICIT Null,
         *                  revoked     [1]     IMPLICIT RevokedInfo,
         *                  unknown     [2]     IMPLICIT UnknownInfo }
         *
         * UnknownInfo ::= NULL
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerTaggedObject(false, m_tagNo, m_value);
    }
}
