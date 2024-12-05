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
        public static MonetaryValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is MonetaryValue monetaryValue)
                return monetaryValue;
            return new MonetaryValue(Asn1Sequence.GetInstance(obj));
        }

        public static MonetaryValue GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MonetaryValue(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static MonetaryValue GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MonetaryValue(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Iso4217CurrencyCode m_currency;
        private readonly DerInteger m_amount;
        private readonly DerInteger m_exponent;

        private MonetaryValue(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_currency = Iso4217CurrencyCode.GetInstance(seq[0]);
            m_amount = DerInteger.GetInstance(seq[1]);
            m_exponent = DerInteger.GetInstance(seq[2]);
        }

        public MonetaryValue(Iso4217CurrencyCode currency, int amount, int exponent)
        {
            m_currency = currency ?? throw new ArgumentNullException(nameof(currency));
            m_amount = new DerInteger(amount);
            m_exponent = new DerInteger(exponent);
        }

		public Iso4217CurrencyCode Currency => m_currency;

        public BigInteger Amount => m_amount.Value;

        public BigInteger Exponent => m_exponent.Value;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_currency, m_amount, m_exponent);
    }
}
