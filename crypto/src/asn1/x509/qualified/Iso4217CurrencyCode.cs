using System;

namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    /**
     * The Iso4217CurrencyCode object.
     * <pre>
     * Iso4217CurrencyCode  ::=  CHOICE {
     *       alphabetic              PrintableString (SIZE 3), --Recommended
     *       numeric              INTEGER (1..999) }
     * -- Alphabetic or numeric currency code as defined in ISO 4217
     * -- It is recommended that the Alphabetic form is used
     * </pre>
     */
    public class Iso4217CurrencyCode
        : Asn1Encodable, IAsn1Choice
    {
        internal const int AlphabeticMaxSize = 3;
        internal const int NumericMinSize = 1;
        internal const int NumericMaxSize = 999;

        public static Iso4217CurrencyCode GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static Iso4217CurrencyCode GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static Iso4217CurrencyCode GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Iso4217CurrencyCode iso4217CurrencyCode)
                return iso4217CurrencyCode;

            DerPrintableString alphabetic = DerPrintableString.GetOptional(element);
            if (alphabetic != null)
                return new Iso4217CurrencyCode(alphabetic.GetString());

            DerInteger numeric = DerInteger.GetOptional(element);
            if (numeric != null)
                return new Iso4217CurrencyCode(numeric.IntValueExact);

            return null;
        }

        public static Iso4217CurrencyCode GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_obj;

        public Iso4217CurrencyCode(int numeric)
        {
            if (numeric > NumericMaxSize || numeric < NumericMinSize)
            {
                throw new ArgumentException("wrong size in numeric code : not in (" + NumericMinSize + ".." +
                    NumericMaxSize + ")");
            }

            m_obj = DerInteger.ValueOf(numeric);
        }

        public Iso4217CurrencyCode(string alphabetic)
        {
            if (alphabetic.Length > AlphabeticMaxSize)
                throw new ArgumentException("wrong size in alphabetic code : max size is " + AlphabeticMaxSize);

            m_obj = new DerPrintableString(alphabetic);
        }

        public bool IsAlphabetic => m_obj is DerPrintableString;

        public string Alphabetic => ((DerPrintableString)m_obj).GetString();

        public int Numeric => ((DerInteger)m_obj).IntValueExact;

        public override Asn1Object ToAsn1Object() => m_obj.ToAsn1Object();
    }
}
