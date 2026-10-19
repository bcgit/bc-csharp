using System;

using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The CertOrEncCert structure of RFC 4210: either a certificate or an encrypted certificate.</summary>
    public class CertOrEncCert
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="CertOrEncCert"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertOrEncCert"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertOrEncCert"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertOrEncCert GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="CertOrEncCert"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertOrEncCert"/>.</returns>
        public static CertOrEncCert GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="CertOrEncCert"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="CertOrEncCert"/>, or null if <paramref name="element"/> is null.</returns>
        public static CertOrEncCert GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CertOrEncCert certOrEncCert)
                return certOrEncCert;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new CertOrEncCert(CmpCertificate.GetInstance(taggedObject.GetExplicitBaseObject()));

                if (taggedObject.HasContextTag(1))
                    return new CertOrEncCert(EncryptedKey.GetInstance(taggedObject.GetExplicitBaseObject()));
            }

            return null;
        }

        /// <summary>Return an <see cref="CertOrEncCert"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertOrEncCert"/>.</returns>
        public static CertOrEncCert GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly CmpCertificate m_certificate;
        private readonly EncryptedKey m_encryptedCert;

        /// <summary>Create a new <see cref="CertOrEncCert"/>.</summary>
        /// <param name="certificate">The certificate.</param>
        public CertOrEncCert(CmpCertificate certificate)
        {
            m_certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        }

        /// <summary>Create a new <see cref="CertOrEncCert"/>.</summary>
        /// <param name="encryptedValue">The encrypted value.</param>
        [Obsolete("Use constructor with EncryptedKey instead")]
        public CertOrEncCert(EncryptedValue encryptedValue)
        {
            m_encryptedCert = new EncryptedKey(
                encryptedValue ?? throw new ArgumentNullException(nameof(encryptedValue)));
        }

        /// <summary>Create a new <see cref="CertOrEncCert"/>.</summary>
        /// <param name="encryptedKey">The encrypted key.</param>
        public CertOrEncCert(EncryptedKey encryptedKey)
        {
            m_encryptedCert = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
        }

        public virtual CmpCertificate Certificate => m_certificate;

        /// <summary>Gets the encrypted cert.</summary>
        public virtual EncryptedKey EncryptedCert => m_encryptedCert;

        /// <summary>Gets a value indicating whether this has encrypted certificate.</summary>
        public virtual bool HasEncryptedCertificate => m_encryptedCert != null;

        /**
         * <pre>
         * CertOrEncCert ::= CHOICE {
         *                      certificate     [0] CMPCertificate,
         *                      encryptedCert   [1] EncryptedKey
         *           }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_certificate != null)
                return new DerTaggedObject(true, 0, m_certificate);
            if (m_encryptedCert != null)
                return new DerTaggedObject(true, 1, m_encryptedCert);
            throw new InvalidOperationException();
        }
    }
}
