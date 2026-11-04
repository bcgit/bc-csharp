using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The PKIFreeText structure of RFC 4210: a sequence of UTF-8 strings.</summary>
    public class PkiFreeText
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PkiFreeText"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PkiFreeText"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PkiFreeText"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PkiFreeText GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiFreeText pkiFreeText)
                return pkiFreeText;
            return new PkiFreeText(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PkiFreeText"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiFreeText"/>.</returns>
        public static PkiFreeText GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiFreeText(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PkiFreeText"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="PkiFreeText"/>, or null if <paramref name="element"/> is null.</returns>
        public static PkiFreeText GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is PkiFreeText pkiFreeText)
                return pkiFreeText;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new PkiFreeText(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="PkiFreeText"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiFreeText"/>.</returns>
        public static PkiFreeText GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiFreeText(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_strings;

        internal PkiFreeText(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            foreach (var element in seq)
            {
                if (!(element is DerUtf8String))
                    throw new ArgumentException("attempt to insert non UTF8 STRING into PkiFreeText");
            }

            m_strings = seq;
        }

        /// <summary>Create a new <see cref="PkiFreeText"/>.</summary>
        /// <param name="p">The p.</param>
        public PkiFreeText(DerUtf8String p)
        {
            m_strings = new DerSequence(p);
        }

        /// <summary>Create a new <see cref="PkiFreeText"/>.</summary>
        /// <param name="p">The p.</param>
        public PkiFreeText(string p)
            : this(new DerUtf8String(p))
        {
        }

        /// <summary>Create a new <see cref="PkiFreeText"/>.</summary>
        /// <param name="strs">The strs.</param>
        public PkiFreeText(DerUtf8String[] strs)
        {
            m_strings = new DerSequence(strs);
        }

        /// <summary>Create a new <see cref="PkiFreeText"/>.</summary>
        /// <param name="strs">The strs.</param>
        public PkiFreeText(string[] strs)
        {
            m_strings = DerSequence.Map(strs, str => new DerUtf8String(str));
        }

        /// <summary>Gets the count.</summary>
        public virtual int Count => m_strings.Count;

        /**
         * Return the UTF8STRING at index.
         *
         * @param index index of the string of interest
         * @return the string at index.
         */
        public DerUtf8String this[int index] => (DerUtf8String)m_strings[index];

        /**
         * <pre>
         * PkiFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => m_strings;
    }
}
