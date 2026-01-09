using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class GcmParameters
        : Asn1Encodable
    {
        private const int DefaultIcvLen = 12;

        public static GcmParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is GcmParameters gcmParameters)
                return gcmParameters;
            return new GcmParameters(Asn1Sequence.GetInstance(obj));
        }

        public static GcmParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GcmParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static GcmParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GcmParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_nonce;
        private readonly int m_icvLen;

        private GcmParameters(Asn1Sequence seq)
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

        public GcmParameters(byte[] nonce, int icvLen)
        {
            m_nonce = DerOctetString.FromContents(nonce);
            m_icvLen = icvLen;
        }

        public byte[] GetNonce() => Arrays.Clone(m_nonce.GetOctets());

        public int IcvLen => m_icvLen;

        public override Asn1Object ToAsn1Object()
        {
            return m_icvLen == DefaultIcvLen
                ?  new DerSequence(m_nonce)
                :  new DerSequence(m_nonce, DerInteger.ValueOf(m_icvLen));
        }
    }
}
