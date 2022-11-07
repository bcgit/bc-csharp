using System;
using System.Globalization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class Time
        : Asn1Encodable, IAsn1Choice
    {
        private readonly Asn1Object time;

		public static Time GetInstance(
            Asn1TaggedObject	obj,
            bool				explicitly)
        {
            return GetInstance(obj.GetObject());
        }

		public Time(
            Asn1Object time)
        {
            if (time == null)
                throw new ArgumentNullException("time");
            if (!(time is Asn1UtcTime) && !(time is Asn1GeneralizedTime))
                throw new ArgumentException("unknown object passed to Time");

            this.time = time;
        }

		/**
         * creates a time object from a given date - if the date is between 1950
         * and 2049 a UTCTime object is Generated, otherwise a GeneralizedTime
         * is used.
         */
        public Time(DateTime date)
        {
            DateTime d = date.ToUniversalTime();

			if (d.Year < 1950 || d.Year > 2049)
            {
                time = new DerGeneralizedTime(d);
            }
            else
            {
                time = new DerUtcTime(d);
            }
        }

		public static Time GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Time time)
                return time;
			if (obj is Asn1UtcTime utcTime)
                return new Time(utcTime);
			if (obj is Asn1GeneralizedTime generalizedTime)
                return new Time(generalizedTime);

            throw new ArgumentException("unknown object in factory: " + Platform.GetTypeName(obj), "obj");
        }

		public string TimeString
        {
			get
			{
				if (time is Asn1UtcTime utcTime)
					return utcTime.AdjustedTimeString;

                return ((Asn1GeneralizedTime)time).GetTime();
			}
        }

		public DateTime Date
        {
			get
			{
				try
				{
					if (time is Asn1UtcTime utcTime)
						return utcTime.ToAdjustedDateTime();

					return ((Asn1GeneralizedTime)time).ToDateTime();
				}
				catch (FormatException e)
				{
					// this should never happen
					throw new InvalidOperationException("invalid date string: " + e.Message);
				}
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
            return time;
        }
    }
}
