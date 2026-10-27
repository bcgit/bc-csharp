using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The parameters of RC2 in CBC mode: an optional version and an initialization vector.</summary>
    public class RC2CbcParameter
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="RC2CbcParameter"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="RC2CbcParameter"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="RC2CbcParameter"/>, or null if <paramref name="obj"/> is null.</returns>
        public static RC2CbcParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RC2CbcParameter rc2CbcParameter)
                return rc2CbcParameter;
            return new RC2CbcParameter(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="RC2CbcParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RC2CbcParameter"/>.</returns>
        public static RC2CbcParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RC2CbcParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="RC2CbcParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RC2CbcParameter"/>.</returns>
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
            m_iv = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="RC2CbcParameter"/>.</summary>
        /// <param name="iv">The initialization vector.</param>
        public RC2CbcParameter(byte[] iv)
        {
            m_version = null;
            m_iv = DerOctetString.FromContents(iv);
        }

        /// <summary>Create a new <see cref="RC2CbcParameter"/>.</summary>
        /// <param name="parameterVersion">The parameter version.</param>
        /// <param name="iv">The initialization vector.</param>
        public RC2CbcParameter(int parameterVersion, byte[] iv)
        {
            m_version = DerInteger.ValueOf(parameterVersion);
            m_iv = DerOctetString.FromContents(iv);
        }

        /// <summary>Gets the RC 2 parameter version.</summary>
        public BigInteger RC2ParameterVersion => m_version?.Value;

        /// <summary>Gets the RC 2 parameter version data.</summary>
        public DerInteger RC2ParameterVersionData => m_version;

        /// <summary>Gets the IV.</summary>
        public Asn1OctetString IV => m_iv;

        /// <summary>Return the IV.</summary>
        public byte[] GetIV() => Arrays.Clone(m_iv.GetOctets());

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            return m_version == null
                ?  new DerSequence(m_iv)
                :  new DerSequence(m_version, m_iv);
        }
    }
}
