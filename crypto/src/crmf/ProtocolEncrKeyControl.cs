using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>Carrier for a protocol encryption key control.</summary>
    public class ProtocolEncrKeyControl
        : IControl
    {
        private readonly SubjectPublicKeyInfo m_publicKeyInfo;

        /// <summary>
        /// Basic constructor - build from the public key to use for protocol encryption.
        /// </summary>
        /// <param name="publicKeyInfo">The public key to use for protocol encryption.</param>
        public ProtocolEncrKeyControl(SubjectPublicKeyInfo publicKeyInfo)
        {
            m_publicKeyInfo = publicKeyInfo ?? throw new ArgumentNullException(nameof(publicKeyInfo));
        }

        /// <summary>
        /// Return the type of this control.
        /// </summary>
        /// <returns><see cref="CrmfObjectIdentifiers.id_regCtrl_protocolEncrKey"/>.</returns>
        public DerObjectIdentifier Type => CrmfObjectIdentifiers.id_regCtrl_protocolEncrKey;

        /// <summary>
        /// Return the public key associated with this control.
        /// </summary>
        /// <returns>A SubjectPublicKeyInfo structure.</returns>
        public Asn1Encodable Value => m_publicKeyInfo;
    }
}
