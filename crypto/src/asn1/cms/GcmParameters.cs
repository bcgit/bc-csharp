using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class GcmParameters
        : Asn1Encodable
    {
        private const int DefaultIcvLen = 12;

        private readonly byte[] m_nonce;
        private readonly int m_icvLen;

        public static GcmParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is GcmParameters gcmParameters)
                return gcmParameters;
            return new GcmParameters(Asn1Sequence.GetInstance(obj));
        }

        public static GcmParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private GcmParameters(Asn1Sequence seq)
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

        public GcmParameters(byte[] nonce, int icvLen)
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
