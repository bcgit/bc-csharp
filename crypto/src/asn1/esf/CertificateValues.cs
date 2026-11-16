using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.3.1 Certificate Values Attribute Definition
    /// <code>
    /// CertificateValues ::= SEQUENCE OF Certificate
    /// </code>
    /// </remarks>
    public class CertificateValues
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertificateValues"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertificateValues"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertificateValues"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertificateValues GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertificateValues certificateValues)
                return certificateValues;
            return new CertificateValues(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertificateValues"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertificateValues"/>.</returns>
        public static CertificateValues GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificateValues(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CertificateValues"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertificateValues"/>.</returns>
        public static CertificateValues GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificateValues(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_certificates;

        private CertificateValues(Asn1Sequence seq)
        {
            m_certificates = seq;
            m_certificates.MapElements(X509CertificateStructure.GetInstance); // Validate
        }

        /// <summary>Create a new <see cref="CertificateValues"/>.</summary>
        /// <param name="certificates">The certificates.</param>
        public CertificateValues(params X509CertificateStructure[] certificates)
        {
            m_certificates = DerSequence.FromElements(certificates);
        }

        /// <summary>Create a new <see cref="CertificateValues"/>.</summary>
        /// <param name="certificates">The certificates.</param>
        public CertificateValues(IEnumerable<X509CertificateStructure> certificates)
        {
            if (certificates == null)
                throw new ArgumentNullException(nameof(certificates));

            m_certificates = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(certificates));
        }

        /// <summary>Create a new <see cref="CertificateValues"/>.</summary>
        /// <param name="certificates">The certificates.</param>
        public CertificateValues(IReadOnlyCollection<X509CertificateStructure> certificates)
        {
            if (certificates == null)
                throw new ArgumentNullException(nameof(certificates));

            m_certificates = DerSequence.FromCollection(certificates);
        }

        /// <summary>Return the certificates.</summary>
        public X509CertificateStructure[] GetCertificates() =>
            m_certificates.MapElements(X509CertificateStructure.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_certificates;
    }
}
