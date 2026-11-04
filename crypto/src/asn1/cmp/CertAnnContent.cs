using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     *  CertAnnContent ::= CMPCertificate
     */
    // TODO[api] Remove and just use CmpCertificate
    public class CertAnnContent
        : CmpCertificate
    {
        /// <summary>Return an <see cref="CertAnnContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertAnnContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertAnnContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static new CertAnnContent GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="CertAnnContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertAnnContent"/>.</returns>
        public static new CertAnnContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="CertAnnContent"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="CertAnnContent"/>, or null if <paramref name="element"/> is null.</returns>
        public static new CertAnnContent GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CertAnnContent certAnnContent)
                return certAnnContent;

            X509CertificateStructure x509v3PKCert = X509CertificateStructure.GetOptional(element);
            if (x509v3PKCert != null)
                return new CertAnnContent(x509v3PKCert);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null && taggedObject.HasContextTag() && taggedObject.IsExplicit())
                return new CertAnnContent(taggedObject.TagNo, taggedObject.GetBaseObject());

            return null;
        }

        /// <summary>Return an <see cref="CertAnnContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertAnnContent"/>.</returns>
        public static new CertAnnContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Create a new <see cref="CertAnnContent"/>.</summary>
        /// <param name="type">The type.</param>
        /// <param name="otherCert">The other cert.</param>
        [Obsolete("Use 'GetInstance' from tagged object instead")]
        public CertAnnContent(int type, Asn1Object otherCert)
            : base(type, otherCert)
        {
        }

        private CertAnnContent(int type, Asn1Encodable otherCert)
#pragma warning disable CS0618 // Type or member is obsolete
            : base(type, otherCert)
#pragma warning restore CS0618 // Type or member is obsolete
        {
        }

        /// <summary>Create a new <see cref="CertAnnContent"/>.</summary>
        /// <param name="x509v3PKCert">The x 509 v 3 PK cert.</param>
        public CertAnnContent(X509CertificateStructure x509v3PKCert)
            : base(x509v3PKCert)
        {
        }
    }
}
