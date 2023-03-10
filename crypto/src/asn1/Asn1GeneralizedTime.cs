using System;
using System.Globalization;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>GeneralizedTime ASN.1 type</summary>
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

        private readonly string m_timeString;
        private readonly bool m_timeStringCanonical;
        private readonly DateTime m_dateTime;

        public Asn1GeneralizedTime(string timeString)
        {
            m_timeString = timeString ?? throw new ArgumentNullException(nameof(timeString));
            m_timeStringCanonical = false; // TODO Dynamic check?

            try
            {
                m_dateTime = FromString(timeString);
            }
            catch (FormatException e)
            {
                throw new ArgumentException("invalid date string: " + e.Message);
            }
        }

        public Asn1GeneralizedTime(DateTime dateTime)
        {
            dateTime = dateTime.ToUniversalTime();

            m_dateTime = dateTime;
            m_timeString = ToStringCanonical(dateTime);
            m_timeStringCanonical = true;
        }

        // TODO TimeZoneInfo or other locale-specific constructors?

        internal Asn1GeneralizedTime(byte[] contents)
            : this(Encoding.ASCII.GetString(contents))
        {
        }

        public string TimeString => m_timeString;

        public DateTime ToDateTime()
        {
            return m_dateTime;
        }

        internal byte[] GetContents(int encoding)
        {
            if (encoding == Asn1OutputStream.EncodingDer && !m_timeStringCanonical)
                return Encoding.ASCII.GetBytes(ToStringCanonical(m_dateTime));

            return Encoding.ASCII.GetBytes(m_timeString);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.GeneralizedTime, GetContents(encoding));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, GetContents(encoding));
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.GeneralizedTime,
                GetContents(Asn1OutputStream.EncodingDer));
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new PrimitiveDerEncoding(tagClass, tagNo, GetContents(Asn1OutputStream.EncodingDer));
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            if (!(asn1Object is Asn1GeneralizedTime that))
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

        internal static Asn1GeneralizedTime CreatePrimitive(byte[] contents)
        {
            return new Asn1GeneralizedTime(contents);
        }

        private static DateTime FromString(string s)
        {
            if (s.Length < 10)
                throw new FormatException();

            s = s.Replace(',', '.');

            if (Platform.EndsWith(s, "Z"))
            {
                switch (s.Length)
                {
                case 11: return ParseUtc(s, @"yyyyMMddHH\Z");
                case 13: return ParseUtc(s, @"yyyyMMddHHmm\Z");
                case 15: return ParseUtc(s, @"yyyyMMddHHmmss\Z");
                case 17: return ParseUtc(s, @"yyyyMMddHHmmss.f\Z");
                case 18: return ParseUtc(s, @"yyyyMMddHHmmss.ff\Z");
                case 19: return ParseUtc(s, @"yyyyMMddHHmmss.fff\Z");
                case 20: return ParseUtc(s, @"yyyyMMddHHmmss.ffff\Z");
                case 21: return ParseUtc(s, @"yyyyMMddHHmmss.fffff\Z");
                case 22: return ParseUtc(s, @"yyyyMMddHHmmss.ffffff\Z");
                case 23: return ParseUtc(s, @"yyyyMMddHHmmss.fffffff\Z");
                default:
                    throw new FormatException();
                }
            }

            int signIndex = IndexOfSign(s, System.Math.Max(10, s.Length - 5));

            if (signIndex < 0)
            {
                switch (s.Length)
                {
                case 10: return ParseLocal(s, @"yyyyMMddHH");
                case 12: return ParseLocal(s, @"yyyyMMddHHmm");
                case 14: return ParseLocal(s, @"yyyyMMddHHmmss");
                case 16: return ParseLocal(s, @"yyyyMMddHHmmss.f");
                case 17: return ParseLocal(s, @"yyyyMMddHHmmss.ff");
                case 18: return ParseLocal(s, @"yyyyMMddHHmmss.fff");
                case 19: return ParseLocal(s, @"yyyyMMddHHmmss.ffff");
                case 20: return ParseLocal(s, @"yyyyMMddHHmmss.fffff");
                case 21: return ParseLocal(s, @"yyyyMMddHHmmss.ffffff");
                case 22: return ParseLocal(s, @"yyyyMMddHHmmss.fffffff");
                default:
                    throw new FormatException();
                }
            }

            if (signIndex == s.Length - 5)
            {
                switch (s.Length)
                {
                case 15: return ParseTimeZone(s, @"yyyyMMddHHzzz");
                case 17: return ParseTimeZone(s, @"yyyyMMddHHmmzzz");
                case 19: return ParseTimeZone(s, @"yyyyMMddHHmmsszzz");
                case 21: return ParseTimeZone(s, @"yyyyMMddHHmmss.fzzz");
                case 22: return ParseTimeZone(s, @"yyyyMMddHHmmss.ffzzz");
                case 23: return ParseTimeZone(s, @"yyyyMMddHHmmss.fffzzz");
                case 24: return ParseTimeZone(s, @"yyyyMMddHHmmss.ffffzzz");
                case 25: return ParseTimeZone(s, @"yyyyMMddHHmmss.fffffzzz");
                case 26: return ParseTimeZone(s, @"yyyyMMddHHmmss.ffffffzzz");
                case 27: return ParseTimeZone(s, @"yyyyMMddHHmmss.fffffffzzz");
                default:
                    throw new FormatException();
                }
            }

            if (signIndex == s.Length - 3)
            {
                switch (s.Length)
                {
                case 13: return ParseTimeZone(s, @"yyyyMMddHHzz");
                case 15: return ParseTimeZone(s, @"yyyyMMddHHmmzz");
                case 17: return ParseTimeZone(s, @"yyyyMMddHHmmsszz");
                case 19: return ParseTimeZone(s, @"yyyyMMddHHmmss.fzz");
                case 20: return ParseTimeZone(s, @"yyyyMMddHHmmss.ffzz");
                case 21: return ParseTimeZone(s, @"yyyyMMddHHmmss.fffzz");
                case 22: return ParseTimeZone(s, @"yyyyMMddHHmmss.ffffzz");
                case 23: return ParseTimeZone(s, @"yyyyMMddHHmmss.fffffzz");
                case 24: return ParseTimeZone(s, @"yyyyMMddHHmmss.ffffffzz");
                case 25: return ParseTimeZone(s, @"yyyyMMddHHmmss.fffffffzz");
                default:
                    throw new FormatException();
                }
            }

            throw new FormatException();
        }

        private static int IndexOfSign(string s, int startIndex)
        {
            int index = Platform.IndexOf(s, '+', startIndex);
            if (index < 0)
            {
                index = Platform.IndexOf(s, '-', startIndex);
            }
            return index;
        }

        private static DateTime ParseLocal(string s, string format)
        {
            return DateTime.ParseExact(s, format, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.AssumeLocal);
        }

        private static DateTime ParseTimeZone(string s, string format)
        {
            return DateTime.ParseExact(s, format, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.AdjustToUniversal);
        }

        private static DateTime ParseUtc(string s, string format)
        {
            return DateTime.ParseExact(s, format, DateTimeFormatInfo.InvariantInfo,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);
        }

        private static string ToStringCanonical(DateTime dateTime)
        {
            return dateTime.ToUniversalTime().ToString(@"yyyyMMddHHmmss.FFFFFFFK", DateTimeFormatInfo.InvariantInfo);
        }
    }
}
