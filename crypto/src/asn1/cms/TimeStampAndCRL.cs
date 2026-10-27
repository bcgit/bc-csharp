using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The TimeStampAndCRL structure of RFC 5544.</summary>
    public class TimeStampAndCrl
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="TimeStampAndCrl"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="TimeStampAndCrl"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="TimeStampAndCrl"/>, or null if <paramref name="obj"/> is null.</returns>
        public static TimeStampAndCrl GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TimeStampAndCrl timeStampAndCrl)
                return timeStampAndCrl;
            return new TimeStampAndCrl(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="TimeStampAndCrl"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TimeStampAndCrl"/>.</returns>
        public static TimeStampAndCrl GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampAndCrl(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="TimeStampAndCrl"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TimeStampAndCrl"/>.</returns>
        public static TimeStampAndCrl GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampAndCrl(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly ContentInfo m_timeStamp;
        private readonly CertificateList m_crl;

        /// <summary>Create a new <see cref="TimeStampAndCrl"/>.</summary>
        /// <param name="timeStamp">The time stamp.</param>
        public TimeStampAndCrl(ContentInfo timeStamp)
            : this(timeStamp, null)
        {
        }

        /// <summary>Create a new <see cref="TimeStampAndCrl"/>.</summary>
        /// <param name="timeStamp">The time stamp.</param>
        /// <param name="crl">The crl.</param>
        public TimeStampAndCrl(ContentInfo timeStamp, CertificateList crl)
        {
            m_timeStamp = timeStamp ?? throw new ArgumentNullException(nameof(timeStamp));
            m_crl = crl;
        }

        private TimeStampAndCrl(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_timeStamp = Asn1Utilities.Read(seq, ref pos, ContentInfo.GetInstance);
            m_crl = Asn1Utilities.ReadOptional(seq, ref pos, CertificateList.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the time stamp token.</summary>
        public virtual ContentInfo TimeStampToken => m_timeStamp;

        /// <summary>Gets the crl.</summary>
        public virtual CertificateList Crl => m_crl;

        /// <remarks>
        /// <code>
        /// TimeStampAndCRL::= SEQUENCE {
        ///     timeStamp   TimeStampToken,          -- according to RFC 3161
        ///     crl         CertificateList OPTIONAL -- according to RFC 5280
        /// }
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object()
        {
            return m_crl == null
                ? new DerSequence(m_timeStamp)
                : new DerSequence(m_timeStamp, m_crl);
        }
    }
}
