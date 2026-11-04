using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>
    /// The IssuerAndSerialNumber structure, which identifies a certificate by its issuer and serial number.
    /// </summary>
    public class IssuerAndSerialNumber
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="IssuerAndSerialNumber"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="IssuerAndSerialNumber"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="IssuerAndSerialNumber"/>, or null if <paramref name="obj"/> is null.</returns>
        public static IssuerAndSerialNumber GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is IssuerAndSerialNumber issuerAndSerialNumber)
                return issuerAndSerialNumber;
            return new IssuerAndSerialNumber(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="IssuerAndSerialNumber"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="IssuerAndSerialNumber"/>.</returns>
        public static IssuerAndSerialNumber GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new IssuerAndSerialNumber(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="IssuerAndSerialNumber"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="IssuerAndSerialNumber"/>.</returns>
        public static IssuerAndSerialNumber GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new IssuerAndSerialNumber(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly X509Name m_issuer;
        private readonly DerInteger m_serialNumber;

        private IssuerAndSerialNumber(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_issuer = Asn1Utilities.Read(seq, ref pos, X509Name.GetInstance);
            m_serialNumber = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="IssuerAndSerialNumber"/>.</summary>
        /// <param name="name">The name.</param>
        /// <param name="certSerialNumber">The cert serial number.</param>
        // TODO[api] 'name' => 'issuer', 'certSerialNumber' => 'serialNumber'
        public IssuerAndSerialNumber(X509Name name, BigInteger certSerialNumber)
        {
            m_issuer = name ?? throw new ArgumentNullException(nameof(name));
            m_serialNumber = new DerInteger(certSerialNumber);
        }

        /// <summary>Create a new <see cref="IssuerAndSerialNumber"/>.</summary>
        /// <param name="name">The name.</param>
        /// <param name="certSerialNumber">The cert serial number.</param>
        // TODO[api] 'name' => 'issuer', 'certSerialNumber' => 'serialNumber'
        public IssuerAndSerialNumber(X509Name name, DerInteger certSerialNumber)
        {
            m_issuer = name ?? throw new ArgumentNullException(nameof(name));
            m_serialNumber = certSerialNumber ?? throw new ArgumentNullException(nameof(certSerialNumber));
        }

        /// <summary>Create a new <see cref="IssuerAndSerialNumber"/>.</summary>
        /// <param name="x509CertificateStructure">The x 509 certificate structure.</param>
        public IssuerAndSerialNumber(X509CertificateStructure x509CertificateStructure)
        {
            m_issuer = x509CertificateStructure.Issuer;
            m_serialNumber = x509CertificateStructure.SerialNumber;
        }

        /// <summary>Gets the issuer.</summary>
        public X509Name Issuer => m_issuer;

        /// <summary>Gets the name.</summary>
        [Obsolete("Use 'Issuer' property instead")]
        public X509Name Name => m_issuer;

        /// <summary>Gets the certificate serial number.</summary>
        [Obsolete("Use 'SerialNumber' property instead")]
        public DerInteger CertificateSerialNumber => m_serialNumber;

        /// <summary>Gets the serial number.</summary>
        public DerInteger SerialNumber => m_serialNumber;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_issuer, m_serialNumber);
    }
}
