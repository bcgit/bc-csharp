using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks>
    /// <pre>
    /// PrivateKeyUsagePeriod ::= SEQUENCE
    /// {
    /// notBefore       [0]     GeneralizedTime OPTIONAL,
    /// notAfter        [1]     GeneralizedTime OPTIONAL }
    /// </pre>
    /// </remarks>
    public class PrivateKeyUsagePeriod
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PrivateKeyUsagePeriod"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PrivateKeyUsagePeriod"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PrivateKeyUsagePeriod"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PrivateKeyUsagePeriod GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PrivateKeyUsagePeriod privateKeyUsagePeriod)
                return privateKeyUsagePeriod;
            // TODO[api] Remove this case
            if (obj is X509Extension x509Extension)
                return GetInstance(X509Extension.ConvertValueToObject(x509Extension));
            return new PrivateKeyUsagePeriod(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PrivateKeyUsagePeriod"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PrivateKeyUsagePeriod"/>.</returns>
        public static PrivateKeyUsagePeriod GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PrivateKeyUsagePeriod(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PrivateKeyUsagePeriod"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PrivateKeyUsagePeriod"/>.</returns>
        public static PrivateKeyUsagePeriod GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PrivateKeyUsagePeriod(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1GeneralizedTime m_notBefore, m_notAfter;

        private PrivateKeyUsagePeriod(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_notBefore = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1GeneralizedTime.GetTagged);
            m_notAfter = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1GeneralizedTime.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the not before.</summary>
        public Asn1GeneralizedTime NotBefore => m_notBefore;

        /// <summary>Gets the not after.</summary>
        public Asn1GeneralizedTime NotAfter => m_notAfter;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(false, 0, m_notBefore);
            v.AddOptionalTagged(false, 1, m_notAfter);
            return new DerSequence(v);
        }
    }
}
