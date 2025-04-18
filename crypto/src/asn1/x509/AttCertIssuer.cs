using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class AttCertIssuer
        : Asn1Encodable, IAsn1Choice
    {
        public static AttCertIssuer GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static AttCertIssuer GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(obj, isExplicit, GetInstance);

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

        public AttCertIssuer(
            V2Form v2Form)
        {
            obj = v2Form;
            choiceObj = new DerTaggedObject(false, 0, obj);
        }

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
