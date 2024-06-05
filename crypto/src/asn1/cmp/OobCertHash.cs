using System;

using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     * OOBCertHash ::= SEQUENCE {
     * hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
     * certId      [1] CertId                  OPTIONAL,
     * hashVal         BIT STRING
     * -- hashVal is calculated over the DER encoding of the
     * -- self-signed certificate with the identifier certID.
     * }
     * </pre>
     */
    public class OobCertHash
		: Asn1Encodable
	{
        public static OobCertHash GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OobCertHash oobCertHash)
                return oobCertHash;
            return new OobCertHash(Asn1Sequence.GetInstance(obj));
        }

        public static OobCertHash GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new OobCertHash(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly AlgorithmIdentifier m_hashAlg;
		private readonly CertId m_certId;
		private readonly DerBitString m_hashVal;

		private OobCertHash(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_hashAlg = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, AlgorithmIdentifier.GetInstance);
            m_certId = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, CertId.GetInstance);
			m_hashVal = DerBitString.GetInstance(seq[pos++]);

			if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        public OobCertHash(AlgorithmIdentifier hashAlg, CertId certId, DerBitString hashVal)
        {
            m_hashAlg = hashAlg;
            m_certId = certId;
            m_hashVal = hashVal ?? throw new ArgumentNullException(nameof(hashVal));
        }

		public virtual CertId CertID => m_certId;

        public virtual AlgorithmIdentifier HashAlg => m_hashAlg;

		public virtual DerBitString HashVal => m_hashVal;

		/**
		 * <pre>
		 * OobCertHash ::= SEQUENCE {
		 *                      hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
		 *                      certId      [1] CertId                  OPTIONAL,
		 *                      hashVal         BIT STRING
		 *                      -- hashVal is calculated over the Der encoding of the
		 *                      -- self-signed certificate with the identifier certID.
		 *       }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_hashAlg);
            v.AddOptionalTagged(true, 1, m_certId);
			v.Add(m_hashVal);
			return new DerSequence(v);
		}
	}
}
