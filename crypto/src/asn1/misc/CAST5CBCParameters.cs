using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Misc
{
    public class Cast5CbcParameters
        : Asn1Encodable
    {
        public static Cast5CbcParameters GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is Cast5CbcParameters cast5CbcParameters)
                return cast5CbcParameters;
            return new Cast5CbcParameters(Asn1Sequence.GetInstance(o));
        }

        public static Cast5CbcParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new Cast5CbcParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1OctetString m_iv;
        private readonly DerInteger m_keyLength;

        private Cast5CbcParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_iv = Asn1Utilities.ReadOptional(seq, ref pos, Asn1OctetString.GetOptional)
                ?? new DerOctetString(new byte[8]);
            m_keyLength = DerInteger.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Cast5CbcParameters(byte[] iv, int keyLength)
        {
            m_iv = new DerOctetString(iv ?? new byte[8]);
            m_keyLength = new DerInteger(keyLength);
        }

        public Asn1OctetString IV => m_iv;

        public byte[] GetIV() => Arrays.Clone(m_iv.GetOctets());

        public int KeyLength => m_keyLength.IntValueExact;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * cast5CBCParameters ::= Sequence {
         *                           iv         OCTET STRING DEFAULT 0,
         *                                  -- Initialization vector
         *                           keyLength  Integer
         *                                  -- Key length, in bits
         *                      }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return IsDefaultIV(m_iv)
                ?  new DerSequence(m_keyLength)
                :  new DerSequence(m_iv, m_keyLength);
        }

        private static bool IsDefaultIV(Asn1OctetString iv)
        {
            return iv.GetOctetsLength() == 8
                && Arrays.AreAllZeroes(iv.GetOctets(), 0, 8);
        }
    }
}
