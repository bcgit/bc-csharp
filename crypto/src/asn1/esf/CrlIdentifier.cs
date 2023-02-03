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
		private readonly X509Name m_crlIssuer;
		private readonly Asn1UtcTime m_crlIssuedTime;
		private readonly DerInteger m_crlNumber;

		public static CrlIdentifier GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is CrlIdentifier crlIdentifier)
                return crlIdentifier;
			return new CrlIdentifier(Asn1Sequence.GetInstance(obj));
		}

        public static CrlIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private CrlIdentifier(Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException(nameof(seq));
			if (seq.Count < 2 || seq.Count > 3)
				throw new ArgumentException("Bad sequence size: " + seq.Count, nameof(seq));

			this.m_crlIssuer = X509Name.GetInstance(seq[0]);
			this.m_crlIssuedTime = Asn1UtcTime.GetInstance(seq[1]);

            // Validate crlIssuedTime is in the appropriate year range
            m_crlIssuedTime.ToDateTime(2049);

			if (seq.Count > 2)
			{
				this.m_crlNumber = DerInteger.GetInstance(seq[2]);
			}
		}

        public CrlIdentifier(X509Name crlIssuer, DateTime crlIssuedTime)
            : this(crlIssuer, crlIssuedTime, null)
		{
		}

		public CrlIdentifier(X509Name crlIssuer, DateTime crlIssuedTime, BigInteger crlNumber)
			: this(crlIssuer, new Asn1UtcTime(crlIssuedTime, 2049), crlNumber)
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

        public X509Name CrlIssuer
		{
			get { return m_crlIssuer; }
		}

		public DateTime CrlIssuedTime
		{
			get { return m_crlIssuedTime.ToDateTime(2049); }
		}

		public BigInteger CrlNumber
		{
			get { return m_crlNumber?.Value; }
		}

		public override Asn1Object ToAsn1Object()
		{
			var v = new Asn1EncodableVector(m_crlIssuer.ToAsn1Object(), m_crlIssuedTime);
            v.AddOptional(m_crlNumber);
			return new DerSequence(v);
		}
	}
}
