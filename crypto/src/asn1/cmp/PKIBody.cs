using System;

using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * PKIBody ::= CHOICE {       -- message-specific body elements
     *          ir       [0]  CertReqMessages,        --Initialization Request
     *          ip       [1]  CertRepMessage,         --Initialization Response
     *          cr       [2]  CertReqMessages,        --Certification Request
     *          cp       [3]  CertRepMessage,         --Certification Response
     *          p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
     *          popdecc  [5]  POPODecKeyChallContent, --pop Challenge
     *          popdecr  [6]  POPODecKeyRespContent,  --pop Response
     *          kur      [7]  CertReqMessages,        --Key Update Request
     *          kup      [8]  CertRepMessage,         --Key Update Response
     *          krr      [9]  CertReqMessages,        --Key Recovery Request
     *          krp      [10] KeyRecRepContent,       --Key Recovery Response
     *          rr       [11] RevReqContent,          --Revocation Request
     *          rp       [12] RevRepContent,          --Revocation Response
     *          ccr      [13] CertReqMessages,        --Cross-Cert. Request
     *          ccp      [14] CertRepMessage,         --Cross-Cert. Response
     *          ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
     *          cann     [16] CertAnnContent,         --Certificate Ann.
     *          rann     [17] RevAnnContent,          --Revocation Ann.
     *          crlann   [18] CRLAnnContent,          --CRL Announcement
     *          pkiconf  [19] PKIConfirmContent,      --Confirmation
     *          nested   [20] NestedMessageContent,   --Nested Message
     *          genm     [21] GenMsgContent,          --General Message
     *          genp     [22] GenRepContent,          --General Response
     *          error    [23] ErrorMsgContent,        --Error Message
     *          certConf [24] CertConfirmContent,     --Certificate confirm
     *          pollReq  [25] PollReqContent,         --Polling request
     *          pollRep  [26] PollRepContent          --Polling response
     *      }
     */
    public class PkiBody
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>The <c>TYPE_INIT_REQ</c> constant, with the value <c>0</c>.</summary>
        public const int TYPE_INIT_REQ = 0;
        /// <summary>The <c>TYPE_INIT_REP</c> constant, with the value <c>1</c>.</summary>
        public const int TYPE_INIT_REP = 1;
        /// <summary>The <c>TYPE_CERT_REQ</c> constant, with the value <c>2</c>.</summary>
        public const int TYPE_CERT_REQ = 2;
        /// <summary>The <c>TYPE_CERT_REP</c> constant, with the value <c>3</c>.</summary>
        public const int TYPE_CERT_REP = 3;
        /// <summary>The <c>TYPE_P10_CERT_REQ</c> constant, with the value <c>4</c>.</summary>
        public const int TYPE_P10_CERT_REQ = 4;
        /// <summary>The <c>TYPE_POPO_CHALL</c> constant, with the value <c>5</c>.</summary>
        public const int TYPE_POPO_CHALL = 5;
        /// <summary>The <c>TYPE_POPO_REP</c> constant, with the value <c>6</c>.</summary>
        public const int TYPE_POPO_REP = 6;
        /// <summary>The <c>TYPE_KEY_UPDATE_REQ</c> constant, with the value <c>7</c>.</summary>
        public const int TYPE_KEY_UPDATE_REQ = 7;
        /// <summary>The <c>TYPE_KEY_UPDATE_REP</c> constant, with the value <c>8</c>.</summary>
        public const int TYPE_KEY_UPDATE_REP = 8;
        /// <summary>The <c>TYPE_KEY_RECOVERY_REQ</c> constant, with the value <c>9</c>.</summary>
        public const int TYPE_KEY_RECOVERY_REQ = 9;
        /// <summary>The <c>TYPE_KEY_RECOVERY_REP</c> constant, with the value <c>10</c>.</summary>
        public const int TYPE_KEY_RECOVERY_REP = 10;
        /// <summary>The <c>TYPE_REVOCATION_REQ</c> constant, with the value <c>11</c>.</summary>
        public const int TYPE_REVOCATION_REQ = 11;
        /// <summary>The <c>TYPE_REVOCATION_REP</c> constant, with the value <c>12</c>.</summary>
        public const int TYPE_REVOCATION_REP = 12;
        /// <summary>The <c>TYPE_CROSS_CERT_REQ</c> constant, with the value <c>13</c>.</summary>
        public const int TYPE_CROSS_CERT_REQ = 13;
        /// <summary>The <c>TYPE_CROSS_CERT_REP</c> constant, with the value <c>14</c>.</summary>
        public const int TYPE_CROSS_CERT_REP = 14;
        /// <summary>The <c>TYPE_CA_KEY_UPDATE_ANN</c> constant, with the value <c>15</c>.</summary>
        public const int TYPE_CA_KEY_UPDATE_ANN = 15;
        /// <summary>The <c>TYPE_CERT_ANN</c> constant, with the value <c>16</c>.</summary>
        public const int TYPE_CERT_ANN = 16;
        /// <summary>The <c>TYPE_REVOCATION_ANN</c> constant, with the value <c>17</c>.</summary>
        public const int TYPE_REVOCATION_ANN = 17;
        /// <summary>The <c>TYPE_CRL_ANN</c> constant, with the value <c>18</c>.</summary>
        public const int TYPE_CRL_ANN = 18;
        /// <summary>The <c>TYPE_CONFIRM</c> constant, with the value <c>19</c>.</summary>
        public const int TYPE_CONFIRM = 19;
        /// <summary>The <c>TYPE_NESTED</c> constant, with the value <c>20</c>.</summary>
        public const int TYPE_NESTED = 20;
        /// <summary>The <c>TYPE_GEN_MSG</c> constant, with the value <c>21</c>.</summary>
        public const int TYPE_GEN_MSG = 21;
        /// <summary>The <c>TYPE_GEN_REP</c> constant, with the value <c>22</c>.</summary>
        public const int TYPE_GEN_REP = 22;
        /// <summary>The <c>TYPE_ERROR</c> constant, with the value <c>23</c>.</summary>
        public const int TYPE_ERROR = 23;
        /// <summary>The <c>TYPE_CERT_CONFIRM</c> constant, with the value <c>24</c>.</summary>
        public const int TYPE_CERT_CONFIRM = 24;
        /// <summary>The <c>TYPE_POLL_REQ</c> constant, with the value <c>25</c>.</summary>
        public const int TYPE_POLL_REQ = 25;
        /// <summary>The <c>TYPE_POLL_REP</c> constant, with the value <c>26</c>.</summary>
        public const int TYPE_POLL_REP = 26;

        /// <summary>Return an <see cref="PkiBody"/> from the given object.</summary>
        /// <param name="obj">An <see cref="PkiBody"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="PkiBody"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PkiBody GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="PkiBody"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiBody"/>.</returns>
        public static PkiBody GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="PkiBody"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="PkiBody"/>, or null if <paramref name="element"/> is null.</returns>
        public static PkiBody GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is PkiBody pkiBody)
                return pkiBody;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new PkiBody(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        /// <summary>Return an <see cref="PkiBody"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiBody"/>.</returns>
        public static PkiBody GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static Asn1Encodable GetOptionalBaseObject(Asn1TaggedObject taggedObject)
        {
            if (taggedObject.HasContextTag())
            {
                switch (taggedObject.TagNo)
                {
                case TYPE_INIT_REQ:
                    return CertReqMessages.GetTagged(taggedObject, true);
                case TYPE_INIT_REP:
                    return CertRepMessage.GetTagged(taggedObject, true);
                case TYPE_CERT_REQ:
                    return CertReqMessages.GetTagged(taggedObject, true);
                case TYPE_CERT_REP:
                    return CertRepMessage.GetTagged(taggedObject, true);
                case TYPE_P10_CERT_REQ:
                    return CertificationRequest.GetTagged(taggedObject, true);
                case TYPE_POPO_CHALL:
                    return PopoDecKeyChallContent.GetTagged(taggedObject, true);
                case TYPE_POPO_REP:
                    return PopoDecKeyRespContent.GetTagged(taggedObject, true);
                case TYPE_KEY_UPDATE_REQ:
                    return CertReqMessages.GetTagged(taggedObject, true);
                case TYPE_KEY_UPDATE_REP:
                    return CertRepMessage.GetTagged(taggedObject, true);
                case TYPE_KEY_RECOVERY_REQ:
                    return CertReqMessages.GetTagged(taggedObject, true);
                case TYPE_KEY_RECOVERY_REP:
                    return KeyRecRepContent.GetTagged(taggedObject, true);
                case TYPE_REVOCATION_REQ:
                    return RevReqContent.GetTagged(taggedObject, true);
                case TYPE_REVOCATION_REP:
                    return RevRepContent.GetTagged(taggedObject, true);
                case TYPE_CROSS_CERT_REQ:
                    return CertReqMessages.GetTagged(taggedObject, true);
                case TYPE_CROSS_CERT_REP:
                    return CertRepMessage.GetTagged(taggedObject, true);
                case TYPE_CA_KEY_UPDATE_ANN:
                    return CAKeyUpdAnnContent.GetTagged(taggedObject, true);
                case TYPE_CERT_ANN:
                    return CmpCertificate.GetTagged(taggedObject, true);
                case TYPE_REVOCATION_ANN:
                    return RevAnnContent.GetTagged(taggedObject, true);
                case TYPE_CRL_ANN:
                    return CrlAnnContent.GetTagged(taggedObject, true);
                case TYPE_CONFIRM:
                    return PkiConfirmContent.GetTagged(taggedObject, true);
                case TYPE_NESTED:
                    return PkiMessages.GetTagged(taggedObject, true);
                case TYPE_GEN_MSG:
                    return GenMsgContent.GetTagged(taggedObject, true);
                case TYPE_GEN_REP:
                    return GenRepContent.GetTagged(taggedObject, true);
                case TYPE_ERROR:
                    return ErrorMsgContent.GetTagged(taggedObject, true);
                case TYPE_CERT_CONFIRM:
                    return CertConfirmContent.GetTagged(taggedObject, true);
                case TYPE_POLL_REQ:
                    return PollReqContent.GetTagged(taggedObject, true);
                case TYPE_POLL_REP:
                    return PollRepContent.GetTagged(taggedObject, true);
                }
            }
            return null;
        }

        private readonly int m_tagNo;
        private readonly Asn1Encodable m_baseObject;

        /**
         * Creates a new PkiBody.
         * @param type one of the TYPE_* constants
         * @param content message content
         */
        // TODO[api] Consider marking [Obsolete("Use 'GetInstance' from tagged object instead")]
        public PkiBody(int type, Asn1Encodable content)
            : this(GetBodyForType(type, content), type)
        {
        }

        private PkiBody(Asn1Encodable baseObject, int tagNo)
        {
            m_tagNo = tagNo;
            m_baseObject = baseObject ?? throw new ArgumentNullException(nameof(baseObject));
        }

        private static Asn1Encodable GetBodyForType(int type, Asn1Encodable o)
        {
            switch (type)
            {
            case TYPE_INIT_REQ:
                return CertReqMessages.GetInstance(o);
            case TYPE_INIT_REP:
                return CertRepMessage.GetInstance(o);
            case TYPE_CERT_REQ:
                return CertReqMessages.GetInstance(o);
            case TYPE_CERT_REP:
                return CertRepMessage.GetInstance(o);
            case TYPE_P10_CERT_REQ:
                return CertificationRequest.GetInstance(o);
            case TYPE_POPO_CHALL:
                return PopoDecKeyChallContent.GetInstance(o);
            case TYPE_POPO_REP:
                return PopoDecKeyRespContent.GetInstance(o);
            case TYPE_KEY_UPDATE_REQ:
                return CertReqMessages.GetInstance(o);
            case TYPE_KEY_UPDATE_REP:
                return CertRepMessage.GetInstance(o);
            case TYPE_KEY_RECOVERY_REQ:
                return CertReqMessages.GetInstance(o);
            case TYPE_KEY_RECOVERY_REP:
                return KeyRecRepContent.GetInstance(o);
            case TYPE_REVOCATION_REQ:
                return RevReqContent.GetInstance(o);
            case TYPE_REVOCATION_REP:
                return RevRepContent.GetInstance(o);
            case TYPE_CROSS_CERT_REQ:
                return CertReqMessages.GetInstance(o);
            case TYPE_CROSS_CERT_REP:
                return CertRepMessage.GetInstance(o);
            case TYPE_CA_KEY_UPDATE_ANN:
                return CAKeyUpdAnnContent.GetInstance(o);
            case TYPE_CERT_ANN:
                return CmpCertificate.GetInstance(o);
            case TYPE_REVOCATION_ANN:
                return RevAnnContent.GetInstance(o);
            case TYPE_CRL_ANN:
                return CrlAnnContent.GetInstance(o);
            case TYPE_CONFIRM:
                return PkiConfirmContent.GetInstance(o);
            case TYPE_NESTED:
                return PkiMessages.GetInstance(o);
            case TYPE_GEN_MSG:
                return GenMsgContent.GetInstance(o);
            case TYPE_GEN_REP:
                return GenRepContent.GetInstance(o);
            case TYPE_ERROR:
                return ErrorMsgContent.GetInstance(o);
            case TYPE_CERT_CONFIRM:
                return CertConfirmContent.GetInstance(o);
            case TYPE_POLL_REQ:
                return PollReqContent.GetInstance(o);
            case TYPE_POLL_REP:
                return PollRepContent.GetInstance(o);
            default:
                throw new ArgumentException("unknown tag number: " + type, nameof(type));
            }
        }

        /// <summary>Gets the content.</summary>
        public virtual Asn1Encodable Content => m_baseObject;

        /// <summary>Gets the type.</summary>
        public virtual int Type => m_tagNo;

        /**
         * <pre>
         * PkiBody ::= CHOICE {       -- message-specific body elements
         *        ir       [0]  CertReqMessages,        --Initialization Request
         *        ip       [1]  CertRepMessage,         --Initialization Response
         *        cr       [2]  CertReqMessages,        --Certification Request
         *        cp       [3]  CertRepMessage,         --Certification Response
         *        p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
         *        popdecc  [5]  POPODecKeyChallContent, --pop Challenge
         *        popdecr  [6]  POPODecKeyRespContent,  --pop Response
         *        kur      [7]  CertReqMessages,        --Key Update Request
         *        kup      [8]  CertRepMessage,         --Key Update Response
         *        krr      [9]  CertReqMessages,        --Key Recovery Request
         *        krp      [10] KeyRecRepContent,       --Key Recovery Response
         *        rr       [11] RevReqContent,          --Revocation Request
         *        rp       [12] RevRepContent,          --Revocation Response
         *        ccr      [13] CertReqMessages,        --Cross-Cert. Request
         *        ccp      [14] CertRepMessage,         --Cross-Cert. Response
         *        ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
         *        cann     [16] CertAnnContent,         --Certificate Ann.
         *        rann     [17] RevAnnContent,          --Revocation Ann.
         *        crlann   [18] CRLAnnContent,          --CRL Announcement
         *        pkiconf  [19] PKIConfirmContent,      --Confirmation
         *        nested   [20] NestedMessageContent,   --Nested Message
         *        genm     [21] GenMsgContent,          --General Message
         *        genp     [22] GenRepContent,          --General Response
         *        error    [23] ErrorMsgContent,        --Error Message
         *        certConf [24] CertConfirmContent,     --Certificate confirm
         *        pollReq  [25] PollReqContent,         --Polling request
         *        pollRep  [26] PollRepContent          --Polling response
         * }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerTaggedObject(true, m_tagNo, m_baseObject);
    }
}
