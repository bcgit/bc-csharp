using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>A certificate (and its bag attributes) held in a PKCS#12 store.</summary>
    public class X509CertificateEntry
        : Pkcs12Entry
    {
        private readonly X509Certificate m_certificate;

        /// <summary>Create an entry for the given certificate, with no attributes.</summary>
        /// <param name="cert">The certificate to hold.</param>
        /// <exception cref="ArgumentNullException"><paramref name="cert"/> is null.</exception>
        public X509CertificateEntry(X509Certificate cert)
            : base(new Dictionary<DerObjectIdentifier, Asn1Encodable>())
        {
            m_certificate = cert ?? throw new ArgumentNullException(nameof(cert));
        }

        /// <summary>Create an entry for the given certificate, with the given bag attributes.</summary>
        /// <param name="cert">The certificate to hold.</param>
        /// <param name="attributes">The bag attributes, keyed by attribute object identifier.</param>
        /// <exception cref="ArgumentNullException"><paramref name="cert"/> is null.</exception>
        public X509CertificateEntry(X509Certificate cert, IDictionary<DerObjectIdentifier, Asn1Encodable> attributes)
            : base(attributes)
        {
            m_certificate = cert ?? throw new ArgumentNullException(nameof(cert));
        }

        /// <summary>Gets the certificate held by this entry.</summary>
        public X509Certificate Certificate => m_certificate;

        /// <summary>Two entries are equal if they hold equal certificates; the attributes are not compared.</summary>
        public override bool Equals(object obj) =>
            obj is X509CertificateEntry that && m_certificate.Equals(that.m_certificate);

        /// <summary>Returns a hash code derived from the certificate.</summary>
        public override int GetHashCode() => ~m_certificate.GetHashCode();
    }
}
