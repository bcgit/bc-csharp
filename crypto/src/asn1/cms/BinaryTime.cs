using System;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>
    /// <see href="https://tools.ietf.org/html/rfc6019">RFC 6019</see> <c>BinaryTime</c> type - the unsigned integer
    /// count of seconds since 1970-01-01T00:00:00Z (UTC).
    /// </summary>
    /// <remarks>
    /// <code>
    /// BinaryTime ::= INTEGER (0..MAX)
    /// </code>
    /// Used by other LAMPS specifications that need a compact, monotonically increasing time value as part of an ASN.1
    /// structure (e.g. RFC 9763).
    /// </remarks>
    /// <seealso cref="PkcsObjectIdentifiers.Pkcs9AtBinarySigningTime">CMS signed attribute OID.</seealso>
    public sealed class BinaryTime
        : Asn1Encodable
    {
        public static BinaryTime GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is BinaryTime binaryTime)
                return binaryTime;
            return new BinaryTime(DerInteger.GetInstance(obj));
        }

        public static BinaryTime GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new BinaryTime(DerInteger.GetInstance(taggedObject, declaredExplicit));

        public static BinaryTime GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new BinaryTime(DerInteger.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_time;

        /// <summary>
        /// Construct a BinaryTime carrying the seconds-since-epoch of the supplied <see cref="DateTime"/>.
        /// </summary>
        /// <remarks>
        /// Sub-second components are discarded by truncation toward negative infinity (consistent with
        /// <c>DateTimeUtilities.DateTimeToUnixMs(dateTime) / 1000</c>).
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">
        /// If <paramref name="dateTime"/> is before the epoch (RFC 6019 prohibits negative values).
        /// </exception>
        public BinaryTime(DateTime dateTime)
            : this(DateTimeUtilities.DateTimeToUnixMs(dateTime) / 1000L)
        {
        }

        /// <summary>
        /// Construct a BinaryTime carrying the supplied count of seconds since 1970-01-01T00:00:00Z (UTC).
        /// </summary>
        /// <remarks>
        /// Sub-second components are discarded by truncation toward negative infinity (consistent with
        /// <c>DateTimeUtilities.DateTimeToUnixMs(dateTime) / 1000</c>).
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">
        /// If <paramref name="seconds"/> is negative.
        /// </exception>
        public BinaryTime(long seconds)
            : this(DerInteger.ValueOf(seconds))
        {
        }

        public BinaryTime(DerInteger time)
        {
            if (time == null)
                throw new ArgumentNullException(nameof(time));
            if (time.IsNegative)
                throw new ArgumentOutOfRangeException(nameof(time), "cannot be negative");

            m_time = time;
        }

        /// <summary>
        /// The encoded value as a count of seconds since the Unix epoch. May exceed <c>long.MaxValue</c> on a wildly
        /// out-of-range encoding; callers that only need a <see cref="DateTime"/> may prefer <see cref="GetDateTime"/>
        /// or <see cref="TryGetDateTime(out DateTime)"/>, which reject unrepresentable values.
        /// </summary>
        public DerInteger Time => m_time;

        /// <summary>Convert the encoded value to a <see cref="DateTime"/>.</summary>
        /// <exception cref="ArithmeticException">
        /// If the seconds-since-epoch value cannot be represented in a <see cref="DateTime"/>.
        /// </exception>
        public DateTime GetDateTime()
        {
            if (TryGetDateTime(out var dateTime))
                return dateTime;

            throw new ArithmeticException("BinaryTime out of DateTime range");
        }

        /// <summary>Convert the encoded value to a <see cref="DateTime"/>.</summary>
        /// <returns>
        /// <c>false</c> if the seconds-since-epoch value cannot be represented in a <see cref="DateTime"/>.
        /// </returns>
        public bool TryGetDateTime(out DateTime dateTime)
        {
            if (m_time.TryGetLongValueExact(out var seconds) && seconds <= long.MaxValue / 1000L)
            {
                dateTime = DateTimeUtilities.UnixMsToDateTime(seconds * 1000L);
                return true;
            }

            dateTime = default(DateTime);
            return false;
        }

        public override Asn1Object ToAsn1Object() => m_time;
    }
}
