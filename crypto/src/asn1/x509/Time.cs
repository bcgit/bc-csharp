using System;
using System.Globalization;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The Time choice of RFC 5280: a UTCTime or a GeneralizedTime.</summary>
    public class Time
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="Time"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Time"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Time"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Time GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="Time"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Time"/>.</returns>
        public static Time GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="Time"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Time"/>, or null if <paramref name="element"/> is null.</returns>
        public static Time GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Time time)
                return time;

            Asn1UtcTime utcTime = Asn1UtcTime.GetOptional(element);
            if (utcTime != null)
                return new Time(utcTime);

            Asn1GeneralizedTime generalizedTime = Asn1GeneralizedTime.GetOptional(element);
            if (generalizedTime != null)
                return new Time(generalizedTime);

            return null;
        }

        /// <summary>Return an <see cref="Time"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Time"/>.</returns>
        public static Time GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Object m_timeObject;

        /// <summary>Create a new <see cref="Time"/>.</summary>
        /// <param name="generalizedTime">The generalized time.</param>
        public Time(Asn1GeneralizedTime generalizedTime)
        {
            m_timeObject = generalizedTime ?? throw new ArgumentNullException(nameof(generalizedTime));
        }

        /// <summary>Create a new <see cref="Time"/>.</summary>
        /// <param name="utcTime">The utc time.</param>
        public Time(Asn1UtcTime utcTime)
        {
            if (utcTime == null)
                throw new ArgumentNullException(nameof(utcTime));

            // Validate utcTime is in the appropriate year range
            utcTime.ToDateTime(2049);

            m_timeObject = utcTime;
        }

        /**
         * creates a time object from a given date - if the date is between 1950
         * and 2049 a UTCTime object is Generated, otherwise a GeneralizedTime
         * is used.
         */
        public Time(DateTime date)
        {
            DateTime utc = date.ToUniversalTime();

            if (utc.Year < 1950 || utc.Year > 2049)
            {
                m_timeObject = Rfc5280Asn1Utilities.CreateGeneralizedTime(utc);
            }
            else
            {
                m_timeObject = Rfc5280Asn1Utilities.CreateUtcTime(utc);
            }
        }

        /// <summary>
        /// Return our time as DateTime.
        /// </summary>
        /// <returns>A date time.</returns>
        public DateTime ToDateTime()
        {
            try
            {
                if (m_timeObject is Asn1UtcTime utcTime)
                    return utcTime.ToDateTime(2049);

                return ((Asn1GeneralizedTime)m_timeObject).ToDateTime();
            }
            catch (FormatException e)
            {
                // this should never happen
                throw new InvalidOperationException("invalid date string", e);
            }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * Time ::= CHOICE {
         *             utcTime        UTCTime,
         *             generalTime    GeneralizedTime }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_timeObject;
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            if (m_timeObject is Asn1UtcTime utcTime)
                return utcTime.ToDateTime(2049).ToString(@"yyyyMMddHHmmssK", DateTimeFormatInfo.InvariantInfo);

            if (m_timeObject is Asn1GeneralizedTime generalizedTime)
                return generalizedTime.ToDateTime().ToString(@"yyyyMMddHHmmss.FFFFFFFK", DateTimeFormatInfo.InvariantInfo);

            throw new InvalidOperationException();
        }
    }
}
