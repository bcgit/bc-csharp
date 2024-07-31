using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Ess
{
    public class EssCertID
		: Asn1Encodable
	{
        public static EssCertID GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is EssCertID essCertID)
                return essCertID;
#pragma warning disable CS0618 // Type or member is obsolete
            return new EssCertID(Asn1Sequence.GetInstance(o));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static EssCertID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new EssCertID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static EssCertID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new EssCertID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1OctetString m_certHash;
        private readonly IssuerSerial m_issuerSerial;

        [Obsolete("Use 'GetInstance' instead")]
        public EssCertID(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certHash = Asn1OctetString.GetInstance(seq[pos++]);
            m_issuerSerial = Asn1Utilities.ReadOptional(seq, ref pos, IssuerSerial.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        public EssCertID(byte[] hash)
            : this(hash, null)
        {
        }

        public EssCertID(byte[] hash, IssuerSerial issuerSerial)
        {
            m_certHash = DerOctetString.FromContents(hash);
            m_issuerSerial = issuerSerial;
        }

        public byte[] GetCertHash() => Arrays.Clone(m_certHash.GetOctets());

        public IssuerSerial IssuerSerial => m_issuerSerial;

		/**
		 * <pre>
		 * EssCertID ::= SEQUENCE {
		 *     certHash Hash,
		 *     issuerSerial IssuerSerial OPTIONAL }
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object()
		{
			return m_issuerSerial == null
				?  new DerSequence(m_certHash)
				:  new DerSequence(m_certHash, m_issuerSerial);
		}
	}
}
