using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * OOBCert ::= CMPCertificate
     */
    // TODO[api] Remove and just use CmpCertificate
    public class OobCert
        : CmpCertificate
    {
        /// <summary>Return an <see cref="OobCert"/> from the given object.</summary>
        /// <param name="obj">An <see cref="OobCert"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="OobCert"/>, or null if <paramref name="obj"/> is null.</returns>
        public static new OobCert GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="OobCert"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OobCert"/>.</returns>
        public static new OobCert GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="OobCert"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="OobCert"/>, or null if <paramref name="element"/> is null.</returns>
        public static new OobCert GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is OobCert oobCert)
                return oobCert;

            X509CertificateStructure x509v3PKCert = X509CertificateStructure.GetOptional(element);
            if (x509v3PKCert != null)
                return new OobCert(x509v3PKCert);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null && taggedObject.HasContextTag() && taggedObject.IsExplicit())
            {
#pragma warning disable CS0618 // Type or member is obsolete
                return new OobCert(taggedObject.TagNo, taggedObject.GetBaseObject());
#pragma warning restore CS0618 // Type or member is obsolete
            }

            return null;
        }

        /// <summary>Return an <see cref="OobCert"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OobCert"/>.</returns>
        public static new OobCert GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Create a new <see cref="OobCert"/>.</summary>
        /// <param name="type">The type.</param>
        /// <param name="otherCert">The other cert.</param>
        [Obsolete("Use constructor from Asn1TaggedObject instead")]
        public OobCert(int type, Asn1Encodable otherCert)
            : base(type, otherCert)
        {
        }

        /// <summary>Create a new <see cref="OobCert"/>.</summary>
        /// <param name="x509v3PKCert">The x 509 v 3 PK cert.</param>
        public OobCert(X509CertificateStructure x509v3PKCert)
            : base(x509v3PKCert)
        {
        }
    }
}
