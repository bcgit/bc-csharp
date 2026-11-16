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
        /// <summary>Return an <see cref="BinaryTime"/> from the given object.</summary>
        /// <param name="obj">An <see cref="BinaryTime"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="BinaryTime"/>, or null if <paramref name="obj"/> is null.</returns>
        public static BinaryTime GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is BinaryTime binaryTime)
                return binaryTime;
            return new BinaryTime(DerInteger.GetInstance(obj));
        }

        /// <summary>Return an <see cref="BinaryTime"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="BinaryTime"/>.</returns>
        public static BinaryTime GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new BinaryTime(DerInteger.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="BinaryTime"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="BinaryTime"/>.</returns>
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

        /// <summary>Create a new <see cref="BinaryTime"/>.</summary>
        /// <param name="time">The time.</param>
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

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_time;
    }
}
