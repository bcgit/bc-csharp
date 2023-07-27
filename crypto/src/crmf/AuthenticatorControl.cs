using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>
    /// Carrier for an authenticator control.
    /// </summary>
    public class AuthenticatorControl
        : IControl
    {
        private readonly DerUtf8String m_token;

        /// <summary>
        /// Basic constructor - build from a UTF-8 string representing the token.
        /// </summary>
        /// <param name="token">UTF-8 string representing the token.</param>
        public AuthenticatorControl(DerUtf8String token)
        {
            m_token = token;
        }

        /// <summary>
        /// Basic constructor - build from a string representing the token.
        /// </summary>
        /// <param name="token">string representing the token.</param>
        public AuthenticatorControl(string token)
        {
            m_token = new DerUtf8String(token);
        }

        /// <summary>
        /// Return the type of this control.
        /// </summary>
        public DerObjectIdentifier Type => CrmfObjectIdentifiers.id_regCtrl_authenticator;

        /// <summary>
        /// Return the token associated with this control (a UTF8String).
        /// </summary>
        public Asn1Encodable Value => m_token;
    }
}
