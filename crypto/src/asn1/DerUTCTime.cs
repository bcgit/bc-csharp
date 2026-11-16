using System;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 UTCTime with DER encoding.</summary>
    public class DerUtcTime
        : Asn1UtcTime
    {
        /// <summary>Create a new <see cref="DerUtcTime"/>.</summary>
        /// <param name="timeString">The time string.</param>
        public DerUtcTime(string timeString)
            : base(timeString)
        {
        }

        /// <summary>Create a new <see cref="DerUtcTime"/>.</summary>
        /// <param name="dateTime">The date time.</param>
        [Obsolete("Use `DerUtcTime(DateTime, int)' instead")]
        public DerUtcTime(DateTime dateTime)
            : base(dateTime)
        {
        }

        /// <summary>Create a new <see cref="DerUtcTime"/>.</summary>
        /// <param name="dateTime">The date time.</param>
        /// <param name="twoDigitYearMax">The two digit year max.</param>
        public DerUtcTime(DateTime dateTime, int twoDigitYearMax)
            : base(dateTime, twoDigitYearMax)
        {
        }

        internal DerUtcTime(byte[] contents)
            : base(contents)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.UtcTime,
                GetContents(Asn1OutputStream.EncodingDer));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, GetContents(Asn1OutputStream.EncodingDer));
        }
    }
}
