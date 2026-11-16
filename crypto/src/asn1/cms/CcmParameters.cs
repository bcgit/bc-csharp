using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The CCMParameters structure of RFC 5084: the parameters of AES in CCM mode.</summary>
    public class CcmParameters
        : Asn1Encodable
    {
        private const int DefaultIcvLen = 12;

        /// <summary>Return an <see cref="CcmParameters"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CcmParameters"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CcmParameters"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CcmParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CcmParameters ccmParameters)
                return ccmParameters;
            return new CcmParameters(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CcmParameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CcmParameters"/>.</returns>
        public static CcmParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CcmParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CcmParameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CcmParameters"/>.</returns>
        public static CcmParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CcmParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_nonce;
        private readonly int m_icvLen;

        private CcmParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_nonce = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            DerInteger icvLen = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            m_icvLen = ValidateIcvLen(icvLen);
        }

        /// <summary>Create a new <see cref="CcmParameters"/>.</summary>
        /// <param name="nonce">The nonce.</param>
        /// <param name="icvLen">The icv len.</param>
        public CcmParameters(byte[] nonce, int icvLen)
        {
            m_nonce = DerOctetString.FromContents(nonce);
            m_icvLen = ValidateIcvLenValue(icvLen);
        }

        /// <summary>Return the nonce.</summary>
        public byte[] GetNonce() => Arrays.Clone(m_nonce.GetOctets());

        /// <summary>Gets the icv len.</summary>
        public int IcvLen => m_icvLen;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            return m_icvLen == DefaultIcvLen
                ?  new DerSequence(m_nonce)
                :  new DerSequence(m_nonce, DerInteger.ValueOf(m_icvLen));
        }

        private static int ValidateIcvLen(DerInteger icvLen)
        {
            if (icvLen == null)
                return DefaultIcvLen;

            if (!icvLen.TryGetIntValueExact(out int icvLenValue))
                throw new ArgumentException("Invalid 'aes-ICVlen' (outside Int32 range)");

            return ValidateIcvLenValue(icvLenValue);
        }

        // RFC 5084: AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)
        private static int ValidateIcvLenValue(int icvLen)
        {
            if (icvLen < 4 || icvLen > 16 || (icvLen & 1) != 0)
                throw new ArgumentException("Invalid 'aes-ICVlen': " + icvLen);

            return icvLen;
        }
    }
}
