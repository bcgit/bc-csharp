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

        public static readonly DerInteger DefaultOutputLength = DerInteger.ValueOf(_DefaultOutputLength);
        public static readonly Asn1OctetString DefaultCustomizationString = DerOctetString.Empty;

        /// <summary>Return an <see cref="KMacWithShake128Params"/> from the given object.</summary>
        /// <param name="o">
        /// An <see cref="KMacWithShake128Params"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="KMacWithShake128Params"/>, or null if <paramref name="o"/> is null.</returns>
        public static KMacWithShake128Params GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is KMacWithShake128Params kMacWithShake128Params)
                return kMacWithShake128Params;
            return new KMacWithShake128Params(Asn1Sequence.GetInstance(o));
        }

        /// <summary>Return an <see cref="KMacWithShake128Params"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KMacWithShake128Params"/>.</returns>
        public static KMacWithShake128Params GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KMacWithShake128Params(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="KMacWithShake128Params"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KMacWithShake128Params"/>.</returns>
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

        /// <summary>Create a new <see cref="KMacWithShake128Params"/>.</summary>
        /// <param name="outputLength">The output length.</param>
        public KMacWithShake128Params(int outputLength)
        {
            m_outputLength = DerInteger.ValueOf(outputLength);
            m_customizationString = DefaultCustomizationString;
        }

        /// <summary>Create a new <see cref="KMacWithShake128Params"/>.</summary>
        /// <param name="outputLength">The output length.</param>
        /// <param name="customizationString">The customization string.</param>
        public KMacWithShake128Params(int outputLength, byte[] customizationString)
        {
            m_outputLength = DerInteger.ValueOf(outputLength);
            m_customizationString = DerOctetString.FromContents(customizationString);
        }

        /// <summary>Gets the output length.</summary>
        public int OutputLength => m_outputLength.IntValueExact;

        /// <summary>Gets the customization string.</summary>
        public byte[] CustomizationString => Arrays.Clone(m_customizationString.GetOctets());

        /// <inheritdoc/>
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
