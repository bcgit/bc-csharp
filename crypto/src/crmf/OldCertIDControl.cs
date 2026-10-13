using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>
    /// Carrier for an old certificate ID control, naming the certificate a request is asking to have
    /// replaced - RFC 4211 sec. 6.5.
    /// </summary>
    public class OldCertIDControl
        : IControl
    {
        private readonly CertId m_certId;

        /// <summary>
        /// Basic constructor - build from the ID of the certificate to be replaced.
        /// </summary>
        /// <param name="certId">The issuer and serial number of the certificate to be replaced.</param>
        public OldCertIDControl(CertId certId)
        {
            m_certId = certId ?? throw new ArgumentNullException(nameof(certId));
        }

        /// <summary>
        /// Basic constructor - build from the issuer and serial number of the certificate to be replaced.
        /// </summary>
        /// <param name="issuer">The issuer of the certificate to be replaced.</param>
        /// <param name="serialNumber">The serial number of the certificate to be replaced.</param>
        public OldCertIDControl(X509Name issuer, DerInteger serialNumber)
            : this(new CertId(new GeneralName(issuer), serialNumber))
        {
        }

        /// <summary>Return the type of this control.</summary>
        /// <returns><see cref="CrmfObjectIdentifiers.id_regCtrl_oldCertID"/>.</returns>
        public DerObjectIdentifier Type => CrmfObjectIdentifiers.id_regCtrl_oldCertID;

        /// <summary>Return the certificate ID associated with this control.</summary>
        /// <returns>A <see cref="CertId"/> structure.</returns>
        public Asn1Encodable Value => m_certId;

        /// <summary>Return the certificate ID associated with this control.</summary>
        /// <returns>A <see cref="CertId"/> structure.</returns>
        public CertId CertId => m_certId;
    }
}
