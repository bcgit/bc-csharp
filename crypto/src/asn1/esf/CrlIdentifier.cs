using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// CrlIdentifier ::= SEQUENCE
    /// {
    /// 	crlissuer Name,
    /// 	crlIssuedTime UTCTime,
    /// 	crlNumber INTEGER OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class CrlIdentifier
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CrlIdentifier"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CrlIdentifier"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CrlIdentifier"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CrlIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlIdentifier crlIdentifier)
                return crlIdentifier;
            return new CrlIdentifier(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CrlIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlIdentifier"/>.</returns>
        public static CrlIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlIdentifier(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CrlIdentifier"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="CrlIdentifier"/>, or null if <paramref name="element"/> is null.</returns>
        public static CrlIdentifier GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CrlIdentifier crlIdentifier)
                return crlIdentifier;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new CrlIdentifier(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="CrlIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlIdentifier"/>.</returns>
        public static CrlIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlIdentifier(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly X509Name m_crlIssuer;
        private readonly Asn1UtcTime m_crlIssuedTime;
        private readonly DerInteger m_crlNumber;

        private CrlIdentifier(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_crlIssuer = Asn1Utilities.Read(seq, ref pos, X509Name.GetInstance);
            m_crlIssuedTime = Asn1Utilities.Read(seq, ref pos, Asn1UtcTime.GetInstance);

            // Validate crlIssuedTime is in the appropriate year range
            m_crlIssuedTime.ToDateTime(2049);

            m_crlNumber = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CrlIdentifier"/>.</summary>
        /// <param name="crlIssuer">The crl issuer.</param>
        /// <param name="crlIssuedTime">The crl issued time.</param>
        public CrlIdentifier(X509Name crlIssuer, DateTime crlIssuedTime)
            : this(crlIssuer, crlIssuedTime, null)
        {
        }

        /// <summary>Create a new <see cref="CrlIdentifier"/>.</summary>
        /// <param name="crlIssuer">The crl issuer.</param>
        /// <param name="crlIssuedTime">The crl issued time.</param>
        /// <param name="crlNumber">The crl number.</param>
        public CrlIdentifier(X509Name crlIssuer, DateTime crlIssuedTime, BigInteger crlNumber)
            : this(crlIssuer, Rfc5280Asn1Utilities.CreateUtcTime(crlIssuedTime), crlNumber)
        {
        }

        /// <summary>Create a new <see cref="CrlIdentifier"/>.</summary>
        /// <param name="crlIssuer">The crl issuer.</param>
        /// <param name="crlIssuedTime">The crl issued time.</param>
        public CrlIdentifier(X509Name crlIssuer, Asn1UtcTime crlIssuedTime)
            : this(crlIssuer, crlIssuedTime, null)
        {
        }

        /// <summary>Create a new <see cref="CrlIdentifier"/>.</summary>
        /// <param name="crlIssuer">The crl issuer.</param>
        /// <param name="crlIssuedTime">The crl issued time.</param>
        /// <param name="crlNumber">The crl number.</param>
        public CrlIdentifier(X509Name crlIssuer, Asn1UtcTime crlIssuedTime, BigInteger crlNumber)
        {
            m_crlIssuer = crlIssuer ?? throw new ArgumentNullException(nameof(crlIssuer));
            m_crlIssuedTime = crlIssuedTime ?? throw new ArgumentNullException(nameof(crlIssuedTime));

            if (null != crlNumber)
            {
                m_crlNumber = new DerInteger(crlNumber);
            }

            // Validate crlIssuedTime is in the appropriate year range
            m_crlIssuedTime.ToDateTime(2049);
        }

        /// <summary>Gets the crl issuer.</summary>
        public X509Name CrlIssuer => m_crlIssuer;

        /// <summary>Gets the crl issued time.</summary>
        public DateTime CrlIssuedTime => m_crlIssuedTime.ToDateTime(2049);

        /// <summary>Gets the crl issued time object.</summary>
        public Asn1UtcTime CrlIssuedTimeObject => m_crlIssuedTime;

        /// <summary>Gets the crl number.</summary>
        public BigInteger CrlNumber => m_crlNumber?.Value;

        /// <summary>Gets the crl number object.</summary>
        public DerInteger CrlNumberObject => m_crlNumber;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            var v = new Asn1EncodableVector(3);
            v.Add(m_crlIssuer, m_crlIssuedTime);
            v.AddOptional(m_crlNumber);
            return new DerSequence(v);
        }
    }
}
