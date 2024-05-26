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
        public static readonly DerInteger DontPublish = new DerInteger(0);
        public static readonly DerInteger PleasePublish = new DerInteger(1);

        public static PkiPublicationInfo GetInstance(object obj)
        {
            if (obj is PkiPublicationInfo pkiPublicationInfo)
                return pkiPublicationInfo;

            if (obj != null)
                return new PkiPublicationInfo(Asn1Sequence.GetInstance(obj));

            return null;
        }

        private readonly DerInteger m_action;
        private readonly Asn1Sequence m_pubInfos;

        private PkiPublicationInfo(Asn1Sequence seq)
        {
            m_action = DerInteger.GetInstance(seq[0]);
            if (seq.Count > 1)
            {
                m_pubInfos = Asn1Sequence.GetInstance(seq[1]);
            }
        }

        public PkiPublicationInfo(BigInteger action)
            : this(new DerInteger(action))
        {
        }

        public PkiPublicationInfo(DerInteger action)
        {
            m_action = action;
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

        public virtual DerInteger Action => m_action;

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
            if (m_pubInfos == null)
                return new DerSequence(m_action);

            return new DerSequence(m_action, m_pubInfos);
        }
    }
}
