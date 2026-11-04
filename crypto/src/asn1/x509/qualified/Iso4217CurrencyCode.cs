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

        /// <summary>Return an <see cref="Iso4217CurrencyCode"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="Iso4217CurrencyCode"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Iso4217CurrencyCode"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Iso4217CurrencyCode GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="Iso4217CurrencyCode"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Iso4217CurrencyCode"/>.</returns>
        public static Iso4217CurrencyCode GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="Iso4217CurrencyCode"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Iso4217CurrencyCode"/>, or null if <paramref name="element"/> is null.</returns>
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

        /// <summary>Return an <see cref="Iso4217CurrencyCode"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Iso4217CurrencyCode"/>.</returns>
        public static Iso4217CurrencyCode GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_obj;

        /// <summary>Create a new <see cref="Iso4217CurrencyCode"/>.</summary>
        /// <param name="numeric">The numeric.</param>
        public Iso4217CurrencyCode(int numeric)
        {
            if (numeric > NumericMaxSize || numeric < NumericMinSize)
            {
                throw new ArgumentException("wrong size in numeric code : not in (" + NumericMinSize + ".." +
                    NumericMaxSize + ")");
            }

            m_obj = DerInteger.ValueOf(numeric);
        }

        /// <summary>Create a new <see cref="Iso4217CurrencyCode"/>.</summary>
        /// <param name="alphabetic">The alphabetic.</param>
        public Iso4217CurrencyCode(string alphabetic)
        {
            if (alphabetic.Length > AlphabeticMaxSize)
                throw new ArgumentException("wrong size in alphabetic code : max size is " + AlphabeticMaxSize);

            m_obj = new DerPrintableString(alphabetic);
        }

        /// <summary>Gets a value indicating whether this is alphabetic.</summary>
        public bool IsAlphabetic => m_obj is DerPrintableString;

        /// <summary>Gets the alphabetic.</summary>
        public string Alphabetic => ((DerPrintableString)m_obj).GetString();

        /// <summary>Gets the numeric.</summary>
        public int Numeric => ((DerInteger)m_obj).IntValueExact;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_obj.ToAsn1Object();
    }
}
