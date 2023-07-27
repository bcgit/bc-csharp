using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Crmf
{
    public class RegTokenControl
        : IControl
    {
        private readonly DerUtf8String m_token;

        /// <summary>
        /// Basic constructor - build from a UTF-8 string representing the token.
        /// </summary>
        /// <param name="token">UTF-8 string representing the token.</param>
        public RegTokenControl(DerUtf8String token)
        {
            m_token = token;
        }

        /// <summary>
        /// Basic constructor - build from a string representing the token.
        /// </summary>
        /// <param name="token">string representing the token.</param>
        public RegTokenControl(string token)
        {
            m_token = new DerUtf8String(token);
        }

        /// <summary>
        /// Return the type of this control.
        /// </summary>
        /// <returns>CRMFObjectIdentifiers.id_regCtrl_regToken</returns>
        public DerObjectIdentifier Type => CrmfObjectIdentifiers.id_regCtrl_regToken;

        /// <summary>
        /// Return the token associated with this control (a UTF8String).
        /// </summary>
        /// <returns>a UTF8String.</returns>
        public Asn1Encodable Value => m_token;
    }
}
