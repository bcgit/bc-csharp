using System;
using System.Globalization;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /**
     * UTC time object.
     */
    public class Asn1UtcTime
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(Asn1UtcTime), Asn1Tags.UtcTime) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

		/**
         * return a UTC Time from the passed in object.
         *
         * @exception ArgumentException if the object cannot be converted.
         */
        public static Asn1UtcTime GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is Asn1UtcTime asn1UtcTime)
                return asn1UtcTime;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                Asn1Object asn1Object = asn1Convertible.ToAsn1Object();
                if (asn1Object is Asn1UtcTime converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (Asn1UtcTime)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct UTC time from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj));
        }

        /**
         * return a UTC Time from a tagged object.
         *
         * @param taggedObject the tagged object holding the object we want
         * @param declaredExplicit true if the object is meant to be explicitly tagged false otherwise.
         * @exception ArgumentException if the tagged object cannot be converted.
         */
        public static Asn1UtcTime GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (Asn1UtcTime)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
        }

        private readonly string time;

        /**
         * The correct format for this is YYMMDDHHMMSSZ (it used to be that seconds were
         * never encoded. When you're creating one of these objects from scratch, that's
         * what you want to use, otherwise we'll try to deal with whatever Gets read from
         * the input stream... (this is why the input format is different from the GetTime()
         * method output).
         * <p>
         * @param time the time string.</p>
         */
        public Asn1UtcTime(string time)
        {
			if (time == null)
				throw new ArgumentNullException("time");

			this.time = time;

			try
			{
				ToDateTime();
			}
			catch (FormatException e)
			{
				throw new ArgumentException("invalid date string: " + e.Message);
			}
        }

		/**
         * base constructor from a DateTime object
         */
        public Asn1UtcTime(DateTime time)
        {
            this.time = time.ToUniversalTime().ToString("yyMMddHHmmss", CultureInfo.InvariantCulture) + "Z";
        }

		internal Asn1UtcTime(byte[] contents)
        {
            //
            // explicitly convert to characters
            //
            this.time = Strings.FromAsciiByteArray(contents);
        }

		/**
		 * return the time as a date based on whatever a 2 digit year will return. For
		 * standardised processing use ToAdjustedDateTime().
		 *
		 * @return the resulting date
		 * @exception ParseException if the date string cannot be parsed.
		 */
		public DateTime ToDateTime()
		{
			return ParseDateString(TimeString, @"yyMMddHHmmss'GMT'zzz");
		}

		/**
		* return the time as an adjusted date
		* in the range of 1950 - 2049.
		*
		* @return a date in the range of 1950 to 2049.
		* @exception ParseException if the date string cannot be parsed.
		*/
		public DateTime ToAdjustedDateTime()
		{
			return ParseDateString(AdjustedTimeString, @"yyyyMMddHHmmss'GMT'zzz");
		}

		private DateTime ParseDateString(string dateStr, string formatStr)
		{
			DateTime dt = DateTime.ParseExact(
				dateStr,
				formatStr,
				DateTimeFormatInfo.InvariantInfo);

			return dt.ToUniversalTime();
		}

		/**
         * return the time - always in the form of
         *  YYMMDDhhmmssGMT(+hh:mm|-hh:mm).
         * <p>
         * Normally in a certificate we would expect "Z" rather than "GMT",
         * however adding the "GMT" means we can just use:
         * <pre>
         *     dateF = new SimpleDateFormat("yyMMddHHmmssz");
         * </pre>
         * To read in the time and Get a date which is compatible with our local
         * time zone.</p>
         * <p>
         * <b>Note:</b> In some cases, due to the local date processing, this
         * may lead to unexpected results. If you want to stick the normal
         * convention of 1950 to 2049 use the GetAdjustedTime() method.</p>
         */
        public string TimeString
        {
			get
			{
				//
				// standardise the format.
				//
				if (time.IndexOf('-') < 0 && time.IndexOf('+') < 0)
				{
					if (time.Length == 11)
					{
						return time.Substring(0, 10) + "00GMT+00:00";
					}
					else
					{
						return time.Substring(0, 12) + "GMT+00:00";
					}
				}
				else
				{
					int index = time.IndexOf('-');
					if (index < 0)
					{
						index = time.IndexOf('+');
					}
					string d = time;

					if (index == time.Length - 3)
					{
						d += "00";
					}

					if (index == 10)
					{
						return d.Substring(0, 10) + "00GMT" + d.Substring(10, 3) + ":" + d.Substring(13, 2);
					}
					else
					{
						return d.Substring(0, 12) + "GMT" + d.Substring(12, 3) + ":" +  d.Substring(15, 2);
					}
				}
			}
        }

		/// <summary>
		/// Return a time string as an adjusted date with a 4 digit year.
		/// This goes in the range of 1950 - 2049.
		/// </summary>
		public string AdjustedTimeString
		{
			get
			{
				string d = TimeString;
				string c = d[0] < '5' ? "20" : "19";

				return c + d;
			}
		}

        internal byte[] GetOctets()
        {
            return Strings.ToAsciiByteArray(time);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.UtcTime, GetOctets());
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, GetOctets());
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
		{
            if (!(asn1Object is Asn1UtcTime that))
                return false;

            return this.time == that.time;
        }

		protected override int Asn1GetHashCode()
		{
            return time.GetHashCode();
        }

		public override string ToString()
		{
			return time;
		}

        internal static Asn1UtcTime CreatePrimitive(byte[] contents)
        {
            return new Asn1UtcTime(contents);
        }
    }
}
