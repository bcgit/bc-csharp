using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkcs
{
    public class X509CertificateEntry
        : Pkcs12Entry
    {
        private readonly X509Certificate m_certificate;

        public X509CertificateEntry(X509Certificate cert)
            : base(new Dictionary<DerObjectIdentifier, Asn1Encodable>())
        {
            m_certificate = cert ?? throw new ArgumentNullException(nameof(cert));
        }

        public X509CertificateEntry(X509Certificate cert, IDictionary<DerObjectIdentifier, Asn1Encodable> attributes)
            : base(attributes)
        {
            m_certificate = cert ?? throw new ArgumentNullException(nameof(cert));
        }

        public X509Certificate Certificate => m_certificate;

        public override bool Equals(object obj) =>
            obj is X509CertificateEntry that && m_certificate.Equals(that.m_certificate);

        public override int GetHashCode() => ~m_certificate.GetHashCode();
    }
}
