using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Misc
{
    /// <summary>The parameters of CAST5 in CBC mode: an initialization vector and a key length.</summary>
    public class Cast5CbcParameters
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Cast5CbcParameters"/> from the given object.</summary>
        /// <param name="o">
        /// An <see cref="Cast5CbcParameters"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Cast5CbcParameters"/>, or null if <paramref name="o"/> is null.</returns>
        public static Cast5CbcParameters GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is Cast5CbcParameters cast5CbcParameters)
                return cast5CbcParameters;
            return new Cast5CbcParameters(Asn1Sequence.GetInstance(o));
        }

        /// <summary>Return an <see cref="Cast5CbcParameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Cast5CbcParameters"/>.</returns>
        public static Cast5CbcParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Cast5CbcParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Cast5CbcParameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Cast5CbcParameters"/>.</returns>
        public static Cast5CbcParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Cast5CbcParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_iv;
        private readonly DerInteger m_keyLength;

        private Cast5CbcParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_iv = Asn1Utilities.ReadOptional(seq, ref pos, Asn1OctetString.GetOptional)
                ?? new DerOctetString(new byte[8]);
            m_keyLength = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="Cast5CbcParameters"/>.</summary>
        /// <param name="iv">The initialization vector.</param>
        /// <param name="keyLength">The key length.</param>
        public Cast5CbcParameters(byte[] iv, int keyLength)
        {
            m_iv = new DerOctetString(iv ?? new byte[8]);
            m_keyLength = DerInteger.ValueOf(keyLength);
        }

        /// <summary>Gets the IV.</summary>
        public Asn1OctetString IV => m_iv;

        /// <summary>Return the IV.</summary>
        public byte[] GetIV() => Arrays.Clone(m_iv.GetOctets());

        /// <summary>Gets the key length.</summary>
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
