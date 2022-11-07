using System;
using System.Globalization;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>UTCTime ASN.1 type</summary>
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

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        public static Asn1UtcTime GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (Asn1UtcTime)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
        }

		private readonly string m_timeString;
		private readonly DateTime m_dateTime;
        private readonly bool m_dateTimeLocked;
        private readonly int m_twoDigitYearMax;

		public Asn1UtcTime(string timeString)
		{
			if (timeString == null)
				throw new ArgumentNullException(nameof(timeString));

			m_timeString = timeString;

			try
			{
				m_dateTime = FromString(timeString, out m_twoDigitYearMax);
                m_dateTimeLocked = false;
            }
            catch (FormatException e)
			{
				throw new ArgumentException("invalid date string: " + e.Message);
			}
		}

        [Obsolete("Use `Asn1UtcTime(DateTime, int)' instead")]
		public Asn1UtcTime(DateTime dateTime)
		{
            DateTime utc = dateTime.ToUniversalTime();
            dateTime = new DateTime(utc.Year, utc.Month, utc.Day, utc.Hour, utc.Minute, utc.Second, DateTimeKind.Utc);

            m_dateTime = dateTime;
            m_dateTimeLocked = true;
            m_timeString = ToStringCanonical(dateTime, out m_twoDigitYearMax);
        }

        public Asn1UtcTime(DateTime dateTime, int twoDigitYearMax)
        {
            DateTime utc = dateTime.ToUniversalTime();
            dateTime = new DateTime(utc.Year, utc.Month, utc.Day, utc.Hour, utc.Minute, utc.Second, DateTimeKind.Utc);

            Validate(dateTime, twoDigitYearMax);

            m_dateTime = dateTime;
            m_dateTimeLocked = true;
            m_timeString = ToStringCanonical(dateTime);
            m_twoDigitYearMax = twoDigitYearMax;
        }

        internal Asn1UtcTime(byte[] contents)
            // NOTE: Non-ASCII characters will produce '?' characters, which will fail DateTime parsing
			: this(Encoding.ASCII.GetString(contents))
		{
		}

        public string TimeString => m_timeString;

        public DateTime ToDateTime()
		{
			return m_dateTime;
		}

        public DateTime ToDateTime(int twoDigitYearMax)
        {
            if (InRange(m_dateTime, twoDigitYearMax))
                return m_dateTime;

            if (m_dateTimeLocked)
                throw new InvalidOperationException();

            int twoDigitYear = m_dateTime.Year % 100;
            int twoDigitYearCutoff = twoDigitYearMax % 100;

            int diff = twoDigitYear - twoDigitYearCutoff;
            int newYear = twoDigitYearMax + diff;
            if (diff > 0)
            {
                newYear -= 100;
            }

            return m_dateTime.AddYears(newYear - m_dateTime.Year);
        }

        public DateTime ToDateTime(Calendar calendar)
        {
            return ToDateTime(calendar.TwoDigitYearMax);
        }

        /// <summary>Return an adjusted date in the range of 1950 - 2049.</summary>
        [Obsolete("Use 'ToDateTime(2049)' instead")]
        public DateTime ToAdjustedDateTime()
        {
            return ToDateTime(2049);
        }

        public int TwoDigitYearMax => m_twoDigitYearMax;

        internal byte[] GetContents(int encoding)
        {
            if (encoding == Asn1OutputStream.EncodingDer && m_timeString.Length != 13)
            {
                string canonical = ToStringCanonical(m_dateTime);
                return Encoding.ASCII.GetBytes(canonical);
            }

            return Encoding.ASCII.GetBytes(m_timeString);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.UtcTime, GetContents(encoding));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, GetContents(encoding));
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            if (!(asn1Object is Asn1UtcTime that))
                return false;

            // TODO Performance
            return Arrays.AreEqual(
                this.GetContents(Asn1OutputStream.EncodingDer),
                that.GetContents(Asn1OutputStream.EncodingDer));
        }

        protected override int Asn1GetHashCode()
        {
            // TODO Performance
            return Arrays.GetHashCode(
                this.GetContents(Asn1OutputStream.EncodingDer));
        }

        public override string ToString()
        {
            return m_timeString;
        }

        internal static Asn1UtcTime CreatePrimitive(byte[] contents)
        {
            return new Asn1UtcTime(contents);
        }

        private static DateTime FromString(string s, out int twoDigitYearMax)
        {
            var provider = DateTimeFormatInfo.InvariantInfo;
            twoDigitYearMax = provider.Calendar.TwoDigitYearMax;

            switch (s.Length)
            {
            case 11:
                return DateTime.ParseExact(s, @"yyMMddHHmm\Z", provider,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);
            case 13:
                return DateTime.ParseExact(s, @"yyMMddHHmmss\Z", provider,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);
            case 15:
                return DateTime.ParseExact(s, @"yyMMddHHmmzzz", provider,
                    DateTimeStyles.AdjustToUniversal);
            case 17:
                return DateTime.ParseExact(s, @"yyMMddHHmmsszzz", provider,
                    DateTimeStyles.AdjustToUniversal);
            default:
                throw new FormatException();
            }
        }

        private static bool InRange(DateTime dateTime, int twoDigitYearMax)
        {
            return (uint)(twoDigitYearMax - dateTime.Year) < 100;
        }

        private static string ToStringCanonical(DateTime dateTime, out int twoDigitYearMax)
        {
            var provider = DateTimeFormatInfo.InvariantInfo;
            twoDigitYearMax = provider.Calendar.TwoDigitYearMax;

            Validate(dateTime, twoDigitYearMax);

            return dateTime.ToString(@"yyMMddHHmmss\Z", provider);
        }

        private static string ToStringCanonical(DateTime dateTime)
        {
            return dateTime.ToString(@"yyMMddHHmmss\Z", DateTimeFormatInfo.InvariantInfo);
        }

        private static void Validate(DateTime dateTime, int twoDigitYearMax)
        {
            if (!InRange(dateTime, twoDigitYearMax))
                throw new ArgumentOutOfRangeException(nameof(dateTime));
        }
    }
}
