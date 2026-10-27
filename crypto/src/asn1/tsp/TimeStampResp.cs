using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /// <summary>The TimeStampResp structure of RFC 3161.</summary>
    public class TimeStampResp
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="TimeStampResp"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="TimeStampResp"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="TimeStampResp"/>, or null if <paramref name="obj"/> is null.</returns>
        public static TimeStampResp GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TimeStampResp timeStampResp)
                return timeStampResp;
            return new TimeStampResp(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="TimeStampResp"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TimeStampResp"/>.</returns>
        public static TimeStampResp GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampResp(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="TimeStampResp"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TimeStampResp"/>.</returns>
        public static TimeStampResp GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampResp(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly PkiStatusInfo m_pkiStatusInfo;
        private readonly ContentInfo m_timeStampToken;

        private TimeStampResp(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_pkiStatusInfo = Asn1Utilities.Read(seq, ref pos, PkiStatusInfo.GetInstance);
            m_timeStampToken = Asn1Utilities.ReadOptional(seq, ref pos, ContentInfo.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="TimeStampResp"/>.</summary>
        /// <param name="pkiStatusInfo">The pki status info.</param>
        /// <param name="timeStampToken">The time stamp token.</param>
        public TimeStampResp(PkiStatusInfo pkiStatusInfo, ContentInfo timeStampToken)
        {
            m_pkiStatusInfo = pkiStatusInfo ?? throw new ArgumentNullException(nameof(pkiStatusInfo));
            m_timeStampToken = timeStampToken;
        }

        /// <summary>Gets the status.</summary>
        public PkiStatusInfo Status => m_pkiStatusInfo;

        /// <summary>Gets the time stamp token.</summary>
        public ContentInfo TimeStampToken => m_timeStampToken;

        /**
         * <pre>
         * TimeStampResp ::= SEQUENCE  {
         *   status                  PkiStatusInfo,
         *   timeStampToken          TimeStampToken     OPTIONAL  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_timeStampToken == null
                ?  new DerSequence(m_pkiStatusInfo)
                :  new DerSequence(m_pkiStatusInfo, m_timeStampToken);
        }
    }
}
