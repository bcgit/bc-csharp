using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class CcmParameters
        : Asn1Encodable
    {
        private const int DefaultIcvLen = 12;

        public static CcmParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CcmParameters ccmParameters)
                return ccmParameters;
            return new CcmParameters(Asn1Sequence.GetInstance(obj));
        }

        public static CcmParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CcmParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly byte[] m_nonce;
        private readonly int m_icvLen;

        private CcmParameters(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_nonce = Asn1OctetString.GetInstance(seq[0]).GetOctets();

            if (count > 1)
            {
                m_icvLen = DerInteger.GetInstance(seq[1]).IntValueExact;
            }
            else
            {
                m_icvLen = DefaultIcvLen;
            }
        }

        public CcmParameters(byte[] nonce, int icvLen)
        {
            m_nonce = Arrays.Clone(nonce);
            m_icvLen = icvLen;
        }

        public byte[] GetNonce() => Arrays.Clone(m_nonce);

        public int IcvLen => m_icvLen;

        public override Asn1Object ToAsn1Object()
        {
            var nonce = new DerOctetString(m_nonce);

            return m_icvLen == DefaultIcvLen
                ?   new DerSequence(nonce)
                :   new DerSequence(nonce, new DerInteger(m_icvLen));
        }
    }
}
