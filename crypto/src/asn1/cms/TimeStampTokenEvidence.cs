using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The TimeStampTokenEvidence structure of RFC 5544.</summary>
    public class TimeStampTokenEvidence
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="TimeStampTokenEvidence"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="TimeStampTokenEvidence"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="TimeStampTokenEvidence"/>, or null if <paramref name="obj"/> is null.</returns>
        public static TimeStampTokenEvidence GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TimeStampTokenEvidence timeStampTokenEvidence)
                return timeStampTokenEvidence;
            return new TimeStampTokenEvidence(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="TimeStampTokenEvidence"/> from a tagged object.</summary>
        /// <param name="tagged">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TimeStampTokenEvidence"/>.</returns>
        public static TimeStampTokenEvidence GetInstance(Asn1TaggedObject tagged, bool isExplicit) =>
            new TimeStampTokenEvidence(Asn1Sequence.GetInstance(tagged, isExplicit));

        /// <summary>Return an <see cref="TimeStampTokenEvidence"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TimeStampTokenEvidence"/>.</returns>
        public static TimeStampTokenEvidence GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampTokenEvidence(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly TimeStampAndCrl[] m_timeStampAndCrls;

        /// <summary>Create a new <see cref="TimeStampTokenEvidence"/>.</summary>
        /// <param name="timeStampAndCrls">The time stamp and crls.</param>
        public TimeStampTokenEvidence(TimeStampAndCrl[] timeStampAndCrls)
        {
            if (Arrays.IsNullOrContainsNull(timeStampAndCrls))
                throw new ArgumentNullException(nameof(timeStampAndCrls), "cannot be null, or contain null");

            m_timeStampAndCrls = timeStampAndCrls;
        }

        /// <summary>Create a new <see cref="TimeStampTokenEvidence"/>.</summary>
        /// <param name="timeStampAndCrl">The time stamp and crl.</param>
        public TimeStampTokenEvidence(TimeStampAndCrl timeStampAndCrl)
        {
            m_timeStampAndCrls = new TimeStampAndCrl[]{
                timeStampAndCrl ?? throw new ArgumentNullException(nameof(timeStampAndCrl)) };
        }

        private TimeStampTokenEvidence(Asn1Sequence seq)
        {
            m_timeStampAndCrls = seq.MapElements(TimeStampAndCrl.GetInstance);
        }

        public virtual TimeStampAndCrl[] ToTimeStampAndCrlArray() => (TimeStampAndCrl[])m_timeStampAndCrls.Clone();

        /// <remarks>
        /// <code>
        /// TimeStampTokenEvidence ::= SEQUENCE SIZE(1..MAX) OF TimeStampAndCrl
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_timeStampAndCrls);
    }
}
