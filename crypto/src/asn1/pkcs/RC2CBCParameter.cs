using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class RC2CbcParameter
        : Asn1Encodable
    {
		public static RC2CbcParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RC2CbcParameter rc2CbcParameter)
                return rc2CbcParameter;
            return new RC2CbcParameter(Asn1Sequence.GetInstance(obj));
		}

        public static RC2CbcParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RC2CbcParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static RC2CbcParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RC2CbcParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly Asn1OctetString m_iv;

        private RC2CbcParameter(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);
            m_iv = Asn1OctetString.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public RC2CbcParameter(byte[] iv)
        {
            m_version = null;
            m_iv = new DerOctetString(iv);
        }

		public RC2CbcParameter(int parameterVersion, byte[] iv)
        {
            m_version = new DerInteger(parameterVersion);
            m_iv = new DerOctetString(iv);
        }

        public BigInteger RC2ParameterVersion => m_version?.Value;

        public DerInteger RC2ParameterVersionData => m_version;

        public Asn1OctetString IV => m_iv;

        public byte[] GetIV() => Arrays.Clone(m_iv.GetOctets());

        public override Asn1Object ToAsn1Object()
        {
            return m_version == null
                ?  new DerSequence(m_iv)
                :  new DerSequence(m_version, m_iv);
        }
    }
}
