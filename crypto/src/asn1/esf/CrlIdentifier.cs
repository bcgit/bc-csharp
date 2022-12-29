using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

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
		private readonly X509Name crlIssuer;
		private readonly Asn1UtcTime crlIssuedTime;
		private readonly DerInteger crlNumber;

		public static CrlIdentifier GetInstance(object obj)
		{
			if (obj == null)
				return null;

			if (obj is CrlIdentifier crlIdentifier)
                return crlIdentifier;

			if (obj is Asn1Sequence asn1Sequence)
				return new CrlIdentifier(asn1Sequence);

			throw new ArgumentException("Unknown object in 'CrlIdentifier' factory: " + Platform.GetTypeName(obj),
				nameof(obj));
		}

		private CrlIdentifier(Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException(nameof(seq));
			if (seq.Count < 2 || seq.Count > 3)
				throw new ArgumentException("Bad sequence size: " + seq.Count, nameof(seq));

			this.crlIssuer = X509Name.GetInstance(seq[0]);
			this.crlIssuedTime = Asn1UtcTime.GetInstance(seq[1]);

            // Validate crlIssuedTime is in the appropriate year range
            crlIssuedTime.ToDateTime(2049);

			if (seq.Count > 2)
			{
				this.crlNumber = DerInteger.GetInstance(seq[2]);
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
            this.crlIssuer = crlIssuer ?? throw new ArgumentNullException(nameof(crlIssuer));
            this.crlIssuedTime = crlIssuedTime ?? throw new ArgumentNullException(nameof(crlIssuedTime));

            if (null != crlNumber)
            {
                this.crlNumber = new DerInteger(crlNumber);
            }

            // Validate crlIssuedTime is in the appropriate year range
            this.crlIssuedTime.ToDateTime(2049);
        }

        public X509Name CrlIssuer
		{
			get { return crlIssuer; }
		}

		public DateTime CrlIssuedTime
		{
			get { return crlIssuedTime.ToDateTime(2049); }
		}

		public BigInteger CrlNumber
		{
			get { return crlNumber?.Value; }
		}

		public override Asn1Object ToAsn1Object()
		{
			var v = new Asn1EncodableVector(crlIssuer.ToAsn1Object(), crlIssuedTime);
            v.AddOptional(crlNumber);
			return new DerSequence(v);
		}
	}
}
