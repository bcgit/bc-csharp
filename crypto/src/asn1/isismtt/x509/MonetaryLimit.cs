using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.IsisMtt.X509
{
    /**
	* Monetary limit for transactions. The QcEuMonetaryLimit QC statement MUST be
	* used in new certificates in place of the extension/attribute MonetaryLimit
	* since January 1, 2004. For the sake of backward compatibility with
	* certificates already in use, components SHOULD support MonetaryLimit (as well
	* as QcEuLimitValue).
	* <p/>
	* Indicates a monetary limit within which the certificate holder is authorized
	* to act. (This value DOES NOT express a limit on the liability of the
	* certification authority).
	* <p/>
	* <pre>
	*    MonetaryLimitSyntax ::= SEQUENCE
	*    {
	*      currency PrintableString (SIZE(3)),
	*      amount INTEGER,
	*      exponent INTEGER
	*    }
	* </pre>
	* <p/>
	* currency must be the ISO code.
	* <p/>
	* value = amount�10*exponent
	*/
    public class MonetaryLimit
		: Asn1Encodable
	{
        public static MonetaryLimit GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is MonetaryLimit monetaryLimit)
                return monetaryLimit;
            return new MonetaryLimit(Asn1Sequence.GetInstance(obj));
        }

        public static MonetaryLimit GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MonetaryLimit(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static MonetaryLimit GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MonetaryLimit(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerPrintableString m_currency;
        private readonly DerInteger m_amount;
        private readonly DerInteger m_exponent;

        private MonetaryLimit(Asn1Sequence seq)
		{
            int count = seq.Count;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_currency = DerPrintableString.GetInstance(seq[0]);
			m_amount = DerInteger.GetInstance(seq[1]);
			m_exponent = DerInteger.GetInstance(seq[2]);
		}

        /**
		* Constructor from a given details.
		* <p/>
		* <p/>
		* value = amount�10^exponent
		*
		* @param currency The currency. Must be the ISO code.
		* @param amount   The amount
		* @param exponent The exponent
		*/
        public MonetaryLimit(string currency, int amount, int exponent)
        {
            m_currency = new DerPrintableString(currency, true);
            m_amount = new DerInteger(amount);
            m_exponent = new DerInteger(exponent);
        }

		public virtual string Currency => m_currency.GetString();

		public virtual BigInteger Amount => m_amount.Value;

		public virtual BigInteger Exponent => m_exponent.Value;

		/**
		* Produce an object suitable for an Asn1OutputStream.
		* <p/>
		* Returns:
		* <p/>
		* <pre>
		*    MonetaryLimitSyntax ::= SEQUENCE
		*    {
		*      currency PrintableString (SIZE(3)),
		*      amount INTEGER,
		*      exponent INTEGER
		*    }
		* </pre>
		*
		* @return an Asn1Object
		*/
		public override Asn1Object ToAsn1Object() => new DerSequence(m_currency, m_amount, m_exponent);
	}
}
