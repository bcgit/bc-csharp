using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    /**
    * The MonetaryValue object.
    * <pre>
    * MonetaryValue  ::=  SEQUENCE {
    *       currency              Iso4217CurrencyCode,
    *       amount               INTEGER,
    *       exponent             INTEGER }
    * -- value = amount * 10^exponent
    * </pre>
    */
    public class MonetaryValue
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="MonetaryValue"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="MonetaryValue"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="MonetaryValue"/>, or null if <paramref name="obj"/> is null.</returns>
        public static MonetaryValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is MonetaryValue monetaryValue)
                return monetaryValue;
            return new MonetaryValue(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="MonetaryValue"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="MonetaryValue"/>.</returns>
        public static MonetaryValue GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MonetaryValue(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="MonetaryValue"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="MonetaryValue"/>.</returns>
        public static MonetaryValue GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MonetaryValue(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Iso4217CurrencyCode m_currency;
        private readonly DerInteger m_amount;
        private readonly DerInteger m_exponent;

        private MonetaryValue(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_currency = Asn1Utilities.Read(seq, ref pos, Iso4217CurrencyCode.GetInstance);
            m_amount = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_exponent = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="MonetaryValue"/>.</summary>
        /// <param name="currency">The currency.</param>
        /// <param name="amount">The amount.</param>
        /// <param name="exponent">The exponent.</param>
        public MonetaryValue(Iso4217CurrencyCode currency, int amount, int exponent)
        {
            m_currency = currency ?? throw new ArgumentNullException(nameof(currency));
            m_amount = DerInteger.ValueOf(amount);
            m_exponent = DerInteger.ValueOf(exponent);
        }

        public Iso4217CurrencyCode Currency => m_currency;

        /// <summary>Gets the amount.</summary>
        public BigInteger Amount => m_amount.Value;

        /// <summary>Gets the exponent.</summary>
        public BigInteger Exponent => m_exponent.Value;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_currency, m_amount, m_exponent);
    }
}
