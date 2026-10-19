using Org.BouncyCastle.Asn1.X500;

namespace Org.BouncyCastle.Asn1.IsisMtt.X509
{
    /**
    * Some other information of non-restrictive nature regarding the usage of this
    * certificate.
    *
    * <pre>
    *    AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048))
    * </pre>
    */
    public class AdditionalInformationSyntax
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="AdditionalInformationSyntax"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AdditionalInformationSyntax"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AdditionalInformationSyntax"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AdditionalInformationSyntax GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AdditionalInformationSyntax additionalInformationSyntax)
                return additionalInformationSyntax;
            return new AdditionalInformationSyntax(DirectoryString.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AdditionalInformationSyntax"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AdditionalInformationSyntax"/>.</returns>
        public static AdditionalInformationSyntax GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AdditionalInformationSyntax(DirectoryString.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="AdditionalInformationSyntax"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AdditionalInformationSyntax"/>.</returns>
        public static AdditionalInformationSyntax GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AdditionalInformationSyntax(DirectoryString.GetTagged(taggedObject, declaredExplicit));

        private readonly DirectoryString m_information;

        private AdditionalInformationSyntax(DirectoryString information)
        {
            // TODO Length constraint?
            m_information = information;
        }

        /**
        * Constructor from a given details.
        *
        * @param information The description of the information.
        */
        public AdditionalInformationSyntax(string information)
        {
            // TODO Length constraint?
            m_information = new DirectoryString(information);
        }

        /// <summary>Gets the information.</summary>
        public virtual DirectoryString Information => m_information;

        /**
        * Produce an object suitable for an Asn1OutputStream.
        * <p/>
        * Returns:
        * <p/>
        * <pre>
        *   AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048))
        * </pre>
        *
        * @return an Asn1Object
        */
        public override Asn1Object ToAsn1Object() => m_information.ToAsn1Object();
    }
}
