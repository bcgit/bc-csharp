using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Nist
{
    /// <summary>
    /// KMACwithSHAKE128-params ::= SEQUENCE {
    ///     kMACOutputLength     INTEGER DEFAULT 256, -- Output length in bits
    ///     customizationString  OCTET STRING DEFAULT ''H
    /// } 
    /// </summary>
    public class KMacWithShake128Params
        : Asn1Encodable
    {
        private const int _DefaultOutputLength = 256;

        public static readonly DerInteger DefaultOutputLength = new DerInteger(_DefaultOutputLength);
        public static readonly Asn1OctetString DefaultCustomizationString = DerOctetString.Empty;

        public static KMacWithShake128Params GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is KMacWithShake128Params kMacWithShake128Params)
                return kMacWithShake128Params;
            return new KMacWithShake128Params(Asn1Sequence.GetInstance(o));
        }

        public static KMacWithShake128Params GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KMacWithShake128Params(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static KMacWithShake128Params GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KMacWithShake128Params(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_outputLength;
        private readonly Asn1OctetString m_customizationString;

        private KMacWithShake128Params(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_outputLength = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional)
                ?? DefaultOutputLength;
            m_customizationString = Asn1Utilities.ReadOptional(seq, ref pos, Asn1OctetString.GetOptional)
                ?? DefaultCustomizationString;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public KMacWithShake128Params(int outputLength)
        {
            m_outputLength = new DerInteger(outputLength);
            m_customizationString = DefaultCustomizationString;
        }

        public KMacWithShake128Params(int outputLength, byte[] customizationString)
        {
            m_outputLength = new DerInteger(outputLength);
            m_customizationString = new DerOctetString(customizationString);
        }

        public int OutputLength => m_outputLength.IntValueExact;

        public byte[] CustomizationString => Arrays.Clone(m_customizationString.GetOctets());

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            if (!m_outputLength.HasValue(_DefaultOutputLength))
            {
                v.Add(m_outputLength);
            }
            if (m_customizationString.GetOctetsLength() != 0)
            {
                v.Add(m_customizationString);
            }
            return new DerSequence(v);
        }
    }
}
