using System;

namespace Org.BouncyCastle.Asn1.X9
{
    /// <summary>
    /// The Parameters choice of ANSI X9.62: named curve, implicit parameters or explicit curve parameters.
    /// </summary>
    public class X962Parameters
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="X962Parameters"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="X962Parameters"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="X962Parameters"/>, or null if <paramref name="obj"/> is null.</returns>
        public static X962Parameters GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="X962Parameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="X962Parameters"/>.</returns>
        public static X962Parameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="X962Parameters"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="X962Parameters"/>, or null if <paramref name="element"/> is null.</returns>
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

        /// <summary>Return an <see cref="X962Parameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="X962Parameters"/>.</returns>
        public static X962Parameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Object m_params;

        /// <summary>Create a new <see cref="X962Parameters"/>.</summary>
        /// <param name="ecParameters">The ec parameters.</param>
        public X962Parameters(X9ECParameters ecParameters)
        {
            // TODO[api] Store directly when Parameters property changed
            m_params = ecParameters.ToAsn1Object();
        }

        /// <summary>Create a new <see cref="X962Parameters"/>.</summary>
        /// <param name="namedCurve">The named curve.</param>
        public X962Parameters(DerObjectIdentifier namedCurve)
        {
            m_params = namedCurve;
        }

        /// <summary>Create a new <see cref="X962Parameters"/>.</summary>
        /// <param name="obj">The object.</param>
        public X962Parameters(Asn1Null obj)
        {
            m_params = obj;
        }

        /// <summary>Gets a value indicating whether this is named curve.</summary>
        public bool IsNamedCurve => m_params is DerObjectIdentifier;

        /// <summary>Gets a value indicating whether this is implicitly CA.</summary>
        public bool IsImplicitlyCA => m_params is Asn1Null;

        /// <summary>Gets the named curve.</summary>
        public DerObjectIdentifier NamedCurve => DerObjectIdentifier.GetOptional(m_params);

        /// <summary>Gets the parameters.</summary>
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
