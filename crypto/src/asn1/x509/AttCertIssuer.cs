using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The AttCertIssuer choice of RFC 5755.</summary>
    public class AttCertIssuer
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="AttCertIssuer"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AttCertIssuer"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AttCertIssuer"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AttCertIssuer GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="AttCertIssuer"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttCertIssuer"/>.</returns>
        public static AttCertIssuer GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(obj, isExplicit, GetInstance);

        /// <summary>Return an <see cref="AttCertIssuer"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="AttCertIssuer"/>, or null if <paramref name="element"/> is null.</returns>
        public static AttCertIssuer GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is AttCertIssuer attCertIssuer)
                return attCertIssuer;

            GeneralNames v1Form = GeneralNames.GetOptional(element);
            if (v1Form != null)
                return new AttCertIssuer(v1Form);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new AttCertIssuer(V2Form.GetTagged(taggedObject, false));
            }

            // TODO[api] Remove this handler
            V2Form v2Form = V2Form.GetOptional(element);
            if (v2Form != null)
                return new AttCertIssuer(v2Form);

            return null;
        }

        /// <summary>Return an <see cref="AttCertIssuer"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttCertIssuer"/>.</returns>
        public static AttCertIssuer GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable obj;
        private readonly Asn1Object choiceObj;

        /// <summary>
        /// Don't use this one if you are trying to be RFC 3281 compliant.
        /// Use it for v1 attribute certificates only.
        /// </summary>
        /// <param name="names">Our GeneralNames structure</param>
        public AttCertIssuer(
            GeneralNames names)
        {
            obj = names;
            choiceObj = obj.ToAsn1Object();
        }

        /// <summary>Create a new <see cref="AttCertIssuer"/>.</summary>
        /// <param name="v2Form">The v 2 form.</param>
        public AttCertIssuer(
            V2Form v2Form)
        {
            obj = v2Form;
            choiceObj = new DerTaggedObject(false, 0, obj);
        }

        /// <summary>Gets the issuer.</summary>
        public Asn1Encodable Issuer
        {
            get { return obj; }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  AttCertIssuer ::= CHOICE {
         *       v1Form   GeneralNames,  -- MUST NOT be used in this
         *                               -- profile
         *       v2Form   [0] V2Form     -- v2 only
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return choiceObj;
        }
    }
}
