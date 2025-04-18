using System;
using System.Globalization;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class Time
        : Asn1Encodable, IAsn1Choice
    {
        public static Time GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static Time GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

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

        public static Time GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Object m_timeObject;

        public Time(Asn1GeneralizedTime generalizedTime)
        {
            m_timeObject = generalizedTime ?? throw new ArgumentNullException(nameof(generalizedTime));
        }

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
                throw new InvalidOperationException("invalid date string: " + e.Message);
            }
        }

        [Obsolete("Use 'ToDateTime' instead")]
        public DateTime Date => ToDateTime();

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
