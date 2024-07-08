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

        public static CcmParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CcmParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CcmParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CcmParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_nonce;
        private readonly int m_icvLen;

        private CcmParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_nonce = Asn1OctetString.GetInstance(seq[pos++]);
            DerInteger icvLen = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            m_icvLen = icvLen == null ? DefaultIcvLen : icvLen.IntValueExact;
        }

        public CcmParameters(byte[] nonce, int icvLen)
        {
            m_nonce = new DerOctetString(nonce);
            m_icvLen = icvLen;
        }

        public byte[] GetNonce() => Arrays.Clone(m_nonce.GetOctets());

        public int IcvLen => m_icvLen;

        public override Asn1Object ToAsn1Object()
        {
            return m_icvLen == DefaultIcvLen
                ?  new DerSequence(m_nonce)
                :  new DerSequence(m_nonce, new DerInteger(m_icvLen));
        }
    }
}
