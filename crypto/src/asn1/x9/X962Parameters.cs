using System;

namespace Org.BouncyCastle.Asn1.X9
{
    public class X962Parameters
        : Asn1Encodable, IAsn1Choice
    {
        public static X962Parameters GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static X962Parameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static X962Parameters GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is X962Parameters x962Parameters)
                return x962Parameters;

            X9ECParameters ecParameters = X9ECParameters.GetOptional(element);
            if (ecParameters != null)
                return new X962Parameters(ecParameters);

            DerObjectIdentifier namedCurve = DerObjectIdentifier.GetOptional(element);
            if (namedCurve != null)
                return new X962Parameters(namedCurve);

            Asn1Null implicitlyCA = Asn1Null.GetOptional(element);
            if (implicitlyCA != null)
                return new X962Parameters(implicitlyCA);

            return null;
        }

        public static X962Parameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Object m_params;

        public X962Parameters(X9ECParameters ecParameters)
        {
            // TODO[api] Store directly when Parameters property changed
            m_params = ecParameters.ToAsn1Object();
        }

        public X962Parameters(DerObjectIdentifier namedCurve)
        {
            m_params = namedCurve;
        }

        public X962Parameters(Asn1Null obj)
        {
            m_params = obj;
        }

        public bool IsNamedCurve => m_params is DerObjectIdentifier;

        public bool IsImplicitlyCA => m_params is Asn1Null;

        public DerObjectIdentifier NamedCurve => DerObjectIdentifier.GetOptional(m_params);

        // TODO[api] Change return type to 'Asn1Encodable' (and store X9ECParameters directly - see above)
        public Asn1Object Parameters => m_params;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * Parameters ::= CHOICE {
         *    ecParameters ECParameters,
         *    namedCurve   CURVES.&amp;id({CurveNames}),
         *    implicitlyCA Null
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => m_params;
    }
}
