using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The CMPCertificate structure of RFC 4210: a certificate in one of the supported formats.</summary>
    public class CmpCertificate
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="CmpCertificate"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CmpCertificate"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CmpCertificate"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CmpCertificate GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="CmpCertificate"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CmpCertificate"/>.</returns>
        public static CmpCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="CmpCertificate"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="CmpCertificate"/>, or null if <paramref name="element"/> is null.</returns>
        public static CmpCertificate GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CmpCertificate cmpCertificate)
                return cmpCertificate;

            X509CertificateStructure x509v3PKCert = X509CertificateStructure.GetOptional(element);
            if (x509v3PKCert != null)
                return new CmpCertificate(x509v3PKCert);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null && taggedObject.HasContextTag() && taggedObject.IsExplicit())
            {
#pragma warning disable CS0618 // Type or member is obsolete
                return new CmpCertificate(taggedObject.TagNo, taggedObject.GetBaseObject());
#pragma warning restore CS0618 // Type or member is obsolete
            }

            return null;
        }

        /// <summary>Return an <see cref="CmpCertificate"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CmpCertificate"/>.</returns>
        public static CmpCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly X509CertificateStructure m_x509v3PKCert;

        private readonly int m_otherCertTag;
        private readonly Asn1Encodable m_otherCert;

        /// <summary>Create a new <see cref="CmpCertificate"/>.</summary>
        /// <param name="type">The type.</param>
        /// <param name="otherCert">The other cert.</param>
        [Obsolete("Use 'GetInstance' from tagged object instead")]
        public CmpCertificate(int type, Asn1Encodable otherCert)
        {
            m_x509v3PKCert = null;
            m_otherCertTag = type;
            m_otherCert = otherCert;
        }

        internal CmpCertificate(CmpCertificate other)
        {
            m_x509v3PKCert = other.m_x509v3PKCert;
            m_otherCertTag = other.m_otherCertTag;
            m_otherCert = other.m_otherCert;
        }

        /// <summary>Create a new <see cref="CmpCertificate"/>.</summary>
        /// <param name="x509v3PKCert">The x 509 v 3 PK cert.</param>
        public CmpCertificate(X509CertificateStructure x509v3PKCert)
        {
            if (x509v3PKCert.Version != 3)
                throw new ArgumentException("only version 3 certificates allowed", nameof(x509v3PKCert));

            m_x509v3PKCert = x509v3PKCert;
            m_otherCertTag = -1;
            m_otherCert = null;
        }

        /// <summary>Gets a value indicating whether this is x 509 v 3 PK cert.</summary>
        public virtual bool IsX509v3PKCert => m_x509v3PKCert != null;

        /// <summary>Gets the x 509 v 3 PK cert.</summary>
        public virtual X509CertificateStructure X509v3PKCert => m_x509v3PKCert;

        /// <summary>Gets the other cert tag.</summary>
        public virtual int OtherCertTag => m_otherCertTag;

        /// <summary>Gets the other cert.</summary>
        public virtual Asn1Encodable OtherCert => m_otherCert;

        /**
         * <pre>
         * CMPCertificate ::= CHOICE {
         *            x509v3PKCert    Certificate
         *            otherCert      [tag] EXPLICIT ANY DEFINED BY tag
         *  }
         * </pre>
         * Note: the addition of the explicit tagging is a BC extension. We apologise for the warped syntax, but hopefully you get the idea.
         *
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_x509v3PKCert != null)
                return m_x509v3PKCert.ToAsn1Object();
            if (m_otherCert != null)
                return new DerTaggedObject(true, m_otherCertTag, m_otherCert);
            throw new InvalidOperationException();
        }
    }
}
