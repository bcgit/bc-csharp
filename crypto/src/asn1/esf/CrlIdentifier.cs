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
    /// 	crlissuer		Name,
    /// 	crlIssuedTime	UTCTime,
    /// 	crlNumber		INTEGER OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class CrlIdentifier
		: Asn1Encodable
	{
		public static CrlIdentifier GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is CrlIdentifier crlIdentifier)
                return crlIdentifier;
			return new CrlIdentifier(Asn1Sequence.GetInstance(obj));
		}

        public static CrlIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlIdentifier(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CrlIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlIdentifier(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly X509Name m_crlIssuer;
        private readonly Asn1UtcTime m_crlIssuedTime;
        private readonly DerInteger m_crlNumber;

        private CrlIdentifier(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count < 2 || count > 3)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_crlIssuer = X509Name.GetInstance(seq[0]);
			m_crlIssuedTime = Asn1UtcTime.GetInstance(seq[1]);

            // Validate crlIssuedTime is in the appropriate year range
            m_crlIssuedTime.ToDateTime(2049);

			if (count > 2)
			{
				m_crlNumber = DerInteger.GetInstance(seq[2]);
			}
		}

        public CrlIdentifier(X509Name crlIssuer, DateTime crlIssuedTime)
            : this(crlIssuer, crlIssuedTime, null)
		{
		}

		public CrlIdentifier(X509Name crlIssuer, DateTime crlIssuedTime, BigInteger crlNumber)
			: this(crlIssuer, Rfc5280Asn1Utilities.CreateUtcTime(crlIssuedTime), crlNumber)
		{
		}

        public CrlIdentifier(X509Name crlIssuer, Asn1UtcTime crlIssuedTime)
            : this(crlIssuer, crlIssuedTime, null)
        {
        }

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

        public X509Name CrlIssuer => m_crlIssuer;

		public DateTime CrlIssuedTime => m_crlIssuedTime.ToDateTime(2049);

		public BigInteger CrlNumber => m_crlNumber?.Value;

		public override Asn1Object ToAsn1Object()
		{
			var v = new Asn1EncodableVector(3);
			v.Add(m_crlIssuer, m_crlIssuedTime);
            v.AddOptional(m_crlNumber);
			return new DerSequence(v);
		}
	}
}
