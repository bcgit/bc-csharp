using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /**
     * <pre>
     * PKIPublicationInfo ::= SEQUENCE {
     *                  action     INTEGER {
     *                                 dontPublish (0),
     *                                 pleasePublish (1) },
     *                  pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
     * -- pubInfos MUST NOT be present if action is "dontPublish"
     * -- (if action is "pleasePublish" and pubInfos is omitted,
     * -- "dontCare" is assumed)
     * </pre>
     */
    public class PkiPublicationInfo
        : Asn1Encodable
    {
        public static readonly DerInteger DontPublish = DerInteger.Zero;
        public static readonly DerInteger PleasePublish = DerInteger.One;

        /// <summary>Return an <see cref="PkiPublicationInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PkiPublicationInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PkiPublicationInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PkiPublicationInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiPublicationInfo pkiPublicationInfo)
                return pkiPublicationInfo;
            return new PkiPublicationInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PkiPublicationInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiPublicationInfo"/>.</returns>
        public static PkiPublicationInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiPublicationInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PkiPublicationInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiPublicationInfo"/>.</returns>
        public static PkiPublicationInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiPublicationInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_action;
        private readonly Asn1Sequence m_pubInfos;

        private PkiPublicationInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_action = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_pubInfos = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="PkiPublicationInfo"/>.</summary>
        /// <param name="action">The action.</param>
        public PkiPublicationInfo(BigInteger action)
            : this(new DerInteger(action))
        {
        }

        /// <summary>Create a new <see cref="PkiPublicationInfo"/>.</summary>
        /// <param name="action">The action.</param>
        public PkiPublicationInfo(DerInteger action)
        {
            m_action = action ?? throw new ArgumentNullException(nameof(action));
        }

        /**
         * Constructor with a single pubInfo, assumes pleasePublish as the action.
         *
         * @param pubInfo the pubInfo to be published (can be null if don't care is required).
         */
        public PkiPublicationInfo(SinglePubInfo pubInfo)
            : this(pubInfo != null ? new SinglePubInfo[1]{ pubInfo } : null)
        {
        }

        /**
         * Constructor with multiple pubInfo, assumes pleasePublish as the action.
         *
         * @param pubInfos the pubInfos to be published (can be null if don't care is required).
         */
        public PkiPublicationInfo(SinglePubInfo[] pubInfos)
        {
            m_action = PleasePublish;

            if (pubInfos != null)
            {
                m_pubInfos = new DerSequence(pubInfos);
            }
        }

        /// <summary>Gets the action.</summary>
        public virtual DerInteger Action => m_action;

        /// <summary>Return the pub infos.</summary>
        public virtual SinglePubInfo[] GetPubInfos() => m_pubInfos?.MapElements(SinglePubInfo.GetInstance);

        /**
         * <pre>
         * PkiPublicationInfo ::= SEQUENCE {
         *                  action     INTEGER {
         *                                 dontPublish (0),
         *                                 pleasePublish (1) },
         *                  pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
         * -- pubInfos MUST NOT be present if action is "dontPublish"
         * -- (if action is "pleasePublish" and pubInfos is omitted,
         * -- "dontCare" is assumed)
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_pubInfos == null
                ?  new DerSequence(m_action)
                :  new DerSequence(m_action, m_pubInfos);
        }
    }
}
