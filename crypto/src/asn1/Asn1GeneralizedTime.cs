using System;
using System.Globalization;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /**
     * Base class representing the ASN.1 GeneralizedTime type.
     * <p>
     * The main difference between these and UTC time is a 4 digit year.
     * </p><p>
     * One second resolution date+time on UTC timezone (Z)
     * with 4 digit year (valid from 0001 to 9999).
     * </p><p>
     * Timestamp format is:  yyyymmddHHMMSS'Z'
     * </p><p>
     * <h2>X.690</h2>
     * This is what is called "restricted string",
     * and it uses ASCII characters to encode digits and supplemental data.
     *
     * <h3>11: Restrictions on BER employed by both CER and DER</h3>
     * <h4>11.7 GeneralizedTime </h4>
     * </p><p>
     * <b>11.7.1</b> The encoding shall terminate with a "Z",
     * as described in the ITU-T Rec. X.680 | ISO/IEC 8824-1 clause on
     * GeneralizedTime.
     * </p><p>
     * <b>11.7.2</b> The seconds element shall always be present.
     * </p><p>
     * <b>11.7.3</b> The fractional-seconds elements, if present,
     * shall omit all trailing zeros; if the elements correspond to 0,
     * they shall be wholly omitted, and the decimal point element also
     * shall be omitted.
     * </p>
     */
    public class Asn1GeneralizedTime
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(Asn1GeneralizedTime), Asn1Tags.GeneralizedTime) { }

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

        public static Asn1GeneralizedTime GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is Asn1GeneralizedTime asn1GeneralizedTime)
                return asn1GeneralizedTime;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                Asn1Object asn1Object = asn1Convertible.ToAsn1Object();
                if (asn1Object is Asn1GeneralizedTime converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (Asn1GeneralizedTime)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct generalized time from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        public static Asn1GeneralizedTime GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (Asn1GeneralizedTime)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
        }

        internal readonly byte[] m_contents;

        public Asn1GeneralizedTime(string time)
        {
            m_contents = Strings.ToByteArray(time);

            try
            {
                ToDateTime();
            }
            catch (FormatException e)
            {
                throw new ArgumentException("invalid date string: " + e.Message);
            }
        }

        public Asn1GeneralizedTime(DateTime time)
        {
            DateTime utc = time.ToUniversalTime();
            var formatStr = @"yyyyMMddHHmmss\Z";
            var formatProvider = DateTimeFormatInfo.InvariantInfo;
            string utcString = utc.ToString(formatStr, formatProvider);
            m_contents = Strings.ToByteArray(utcString);
        }

        // TODO Custom locale constructor?
        //public Asn1GeneralizedTime(DateTime time, Locale locale)
        //{
        //    SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss\Z", locale);

        //    dateF.setTimeZone(new SimpleTimeZone(0, "Z"));

        //    this.contents = Strings.toByteArray(dateF.format(time));
        //}

        internal Asn1GeneralizedTime(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 4)
                throw new ArgumentException("GeneralizedTime string too short", nameof(bytes));

            m_contents = bytes;

            if (!(IsDigit(0) && IsDigit(1) && IsDigit(2) && IsDigit(3)))
                throw new ArgumentException("illegal characters in GeneralizedTime string", nameof(bytes));
        }

        public string TimeString => Strings.FromByteArray(m_contents);

        public string GetTime()
        {
            string stime = Strings.FromByteArray(m_contents);

            //
            // standardise the format.
            //
            if (stime[stime.Length - 1] == 'Z')
                return stime.Substring(0, stime.Length - 1) + "GMT+00:00";

            int signPos = stime.Length - 6;
            char sign = stime[signPos];
            if ((sign == '-' || sign == '+') && stime.IndexOf("GMT") == signPos - 3)
            {
                // already a GMT string!
                return stime;
            }

            signPos = stime.Length - 5;
            sign = stime[signPos];
            if (sign == '-' || sign == '+')
            {
                return stime.Substring(0, signPos)
                    + "GMT"
                    + stime.Substring(signPos, 3)
                    + ":"
                    + stime.Substring(signPos + 3);
            }

            signPos = stime.Length - 3;
            sign = stime[signPos];
            if (sign == '-' || sign == '+')
            {
                return stime.Substring(0, signPos)
                    + "GMT"
                    + stime.Substring(signPos)
                    + ":00";
            }

            return stime + CalculateGmtOffset(stime);
        }

        private string CalculateGmtOffset(string stime)
        {
            TimeZoneInfo timeZone = TimeZoneInfo.Local;
            TimeSpan offset = timeZone.BaseUtcOffset;

            string sign = "+";
            if (offset.CompareTo(TimeSpan.Zero) < 0)
            {
                sign = "-";
                offset = offset.Duration();
            }

            int hours = offset.Hours;
            int minutes = offset.Minutes;

            try
            {
                if (timeZone.SupportsDaylightSavingTime)
                {
                    string d = stime + "GMT" + sign + Convert(hours) + ":" + Convert(minutes);
                    string formatStr = CalculateGmtFormatString(d);

                    DateTime dateTime = ParseDateString(d, formatStr, makeUniversal: true);

                    if (timeZone.IsDaylightSavingTime(dateTime))
                    {
                        hours += sign.Equals("+") ? 1 : -1;
                    }
                }
            }
            catch (Exception)
            {
                // we'll do our best and ignore daylight savings
            }

            return "GMT" + sign + Convert(hours) + ":" + Convert(minutes);
        }

        private string CalculateGmtFormatString(string d)
        {
            if (HasFractionalSeconds())
            {
                int fCount = Platform.IndexOf(d, "GMT") - 1 - d.IndexOf('.');
                return @"yyyyMMddHHmmss." + FString(fCount) + @"'GMT'zzz";
            }

            if (HasSeconds())
                return @"yyyyMMddHHmmss'GMT'zzz";

            if (HasMinutes())
                return @"yyyyMMddHHmm'GMT'zzz";

            return @"yyyyMMddHH'GMT'zzz";
        }

        private string Convert(int time)
        {
            if (time < 10)
                return "0" + time;

            return time.ToString();
        }

        public DateTime ToDateTime()
        {
            string formatStr;
            string stime = Strings.FromByteArray(m_contents);
            string d = stime;
            bool makeUniversal = false;

            if (Platform.EndsWith(stime, "Z"))
            {
                if (HasFractionalSeconds())
                {
                    int fCount = d.Length - d.IndexOf('.') - 2;
                    formatStr = @"yyyyMMddHHmmss." + FString(fCount) + @"\Z";
                }
                else if (HasSeconds())
                {
                    formatStr = @"yyyyMMddHHmmss\Z";
                }
                else if (HasMinutes())
                {
                    formatStr = @"yyyyMMddHHmm\Z";
                }
                else
                {
                    formatStr = @"yyyyMMddHH\Z";
                }
            }
            else if (stime.IndexOf('-') > 0 || stime.IndexOf('+') > 0)
            {
                d = GetTime();
                formatStr = CalculateGmtFormatString(d);
                makeUniversal = true;
            }
            else
            {
                if (HasFractionalSeconds())
                {
                    int fCount = d.Length - 1 - d.IndexOf('.');
                    formatStr = @"yyyyMMddHHmmss." + FString(fCount);
                }
                else if (HasSeconds())
                {
                    formatStr = @"yyyyMMddHHmmss";
                }
                else if (HasMinutes())
                {
                    formatStr = @"yyyyMMddHHmm";
                }
                else
                {
                    formatStr = @"yyyyMMddHH";
                }
            }

            // TODO Epoch adjustment?
            //return DateUtil.epochAdjust(dateF.parse(d));
            return ParseDateString(d, formatStr, makeUniversal);
        }

        protected bool HasFractionalSeconds()
        {
            return m_contents.Length > 14 && m_contents[14] == '.';
        }

        protected bool HasSeconds()
        {
            return IsDigit(12) && IsDigit(13);
        }

        protected bool HasMinutes()
        {
            return IsDigit(10) && IsDigit(11);
        }

        private bool IsDigit(int pos)
        {
            return m_contents.Length > pos && m_contents[pos] >= '0' && m_contents[pos] <= '9';
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.GeneralizedTime, GetDerTime());

            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.GeneralizedTime, m_contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return new PrimitiveEncoding(tagClass, tagNo, GetDerTime());

            return new PrimitiveEncoding(tagClass, tagNo, m_contents);
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            if (!(asn1Object is Asn1GeneralizedTime that))
                return false;

            return Arrays.AreEqual(m_contents, that.m_contents);
        }

        protected override int Asn1GetHashCode()
        {
            return Arrays.GetHashCode(m_contents);
        }

        internal static Asn1GeneralizedTime CreatePrimitive(byte[] contents)
        {
            return new Asn1GeneralizedTime(contents);
        }

        internal byte[] GetDerTime()
        {
            if (m_contents[m_contents.Length - 1] != 'Z')
            {
                return m_contents; // TODO: is there a better way?
            }

            if (!HasMinutes())
            {
                byte[] derTime = new byte[m_contents.Length + 4];

                Array.Copy(m_contents, 0, derTime, 0, m_contents.Length - 1);
                Array.Copy(Strings.ToByteArray("0000Z"), 0, derTime, m_contents.Length - 1, 5);

                return derTime;
            }
            else if (!HasSeconds())
            {
                byte[] derTime = new byte[m_contents.Length + 2];

                Array.Copy(m_contents, 0, derTime, 0, m_contents.Length - 1);
                Array.Copy(Strings.ToByteArray("00Z"), 0, derTime, m_contents.Length - 1, 3);

                return derTime;
            }
            else if (HasFractionalSeconds())
            {
                int ind = m_contents.Length - 2;
                while (ind > 0 && m_contents[ind] == '0')
                {
                    ind--;
                }

                if (m_contents[ind] == '.')
                {
                    byte[] derTime = new byte[ind + 1];

                    Array.Copy(m_contents, 0, derTime, 0, ind);
                    derTime[ind] = (byte)'Z';

                    return derTime;
                }
                else
                {
                    byte[] derTime = new byte[ind + 2];

                    Array.Copy(m_contents, 0, derTime, 0, ind + 1);
                    derTime[ind + 1] = (byte)'Z';

                    return derTime;
                }
            }
            else
            {
                return m_contents;
            }
        }

        private static string FString(int count)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < count; ++i)
            {
                sb.Append('f');
            }
            return sb.ToString();
        }

        private static DateTime ParseDateString(string s, string format, bool makeUniversal)
        {
            DateTimeStyles dateTimeStyles = DateTimeStyles.None;
            if (Platform.EndsWith(format, "Z"))
            {
                dateTimeStyles |= DateTimeStyles.AdjustToUniversal;
                dateTimeStyles |= DateTimeStyles.AssumeUniversal;
            }

            DateTime dt = DateTime.ParseExact(s, format, DateTimeFormatInfo.InvariantInfo, dateTimeStyles);

            return makeUniversal ? dt.ToUniversalTime() : dt;
        }
    }
}
