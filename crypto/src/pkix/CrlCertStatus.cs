using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>
    /// The revocation status of a certificate (cert_status, RFC 5280 6.3.2 (b)), as accumulated over the CRLs checked
    /// for it.
    /// </summary>
    /// <remarks>
    /// Unlike the public <c>CertStatus</c>, the reason code is kept apart from whether the certificate is revoked, so
    /// no value found in a CRL can be mistaken for a status. UNDETERMINED is not tracked: it is concluded once CRL
    /// processing ends with the certificate not revoked and the checked CRLs not covering all reasons.
    /// </remarks>
    internal sealed class CrlCertStatus
    {
        // Indexed by CRLReason value
        private static readonly string[] ReasonNames = new string[]
        {
            "unspecified",
            "keyCompromise",
            "cACompromise",
            "affiliationChanged",
            "superseded",
            "cessationOfOperation",
            "certificateHold",
            "unknown",
            "removeFromCRL",
            "privilegeWithdrawn",
            "aACompromise"
        };

        /// <summary>Whether a reason code is one of the CRLReason values defined by RFC 5280 5.3.1.</summary>
        internal static bool IsReasonCodeKnown(int reasonCode)
        {
            return reasonCode >= CrlReason.Unspecified
                && reasonCode <= CrlReason.AACompromise
                && reasonCode != 7; // value 7 is not used (RFC 5280 5.3.1)
        }

        /// <summary>The CRLReason to process a CRL entry by: its reason code if defined, else unspecified.</summary>
        /// <param name="reasonCode">The entry's reason code, or null if absent or outside the int range.</param>
        internal static int GetReason(int? reasonCode) =>
            reasonCode.HasValue && IsReasonCodeKnown(reasonCode.Value) ? reasonCode.Value : CrlReason.Unspecified;

        private DateTime? m_revocationDate;
        private int? m_reasonCode;

        internal bool IsRevoked => m_revocationDate.HasValue;

        /// <summary>The CRL entry's revocation date, or null if the certificate has not been found revoked.</summary>
        internal DateTime? RevocationDate => m_revocationDate;

        /// <summary>
        /// The CRL entry's reason code as given, or null if it is absent, outside the int range, or the certificate has
        /// not been found revoked.
        /// </summary>
        internal int? ReasonCode => m_reasonCode;

        /// <summary>The CRLReason to process the revocation by (see <see cref="GetReason"/>).</summary>
        internal int Reason => GetReason(m_reasonCode);

        /// <summary>
        /// The reason for a revocation message: the name of <see cref="Reason"/>, or the reason code as given if it is
        /// not a defined CRLReason.
        /// </summary>
        internal string GetReasonText()
        {
            int? reasonCode = m_reasonCode;
            if (reasonCode.HasValue && !IsReasonCodeKnown(reasonCode.Value))
                return $"(unknown code: {reasonCode.Value})";

            return ReasonNames[Reason];
        }

        internal void SetRevoked(DateTime revocationDate, int? reasonCode)
        {
            m_revocationDate = revocationDate;
            m_reasonCode = reasonCode;
        }

        /// <summary>Clear a removeFromCRL revocation (RFC 5280 6.3.3 (k)).</summary>
        internal void SetUnrevoked()
        {
            m_revocationDate = null;
            m_reasonCode = null;
        }
    }
}
