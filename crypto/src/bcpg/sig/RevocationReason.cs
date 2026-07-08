using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Signature Subpacket for encoding the reason why a key was revoked.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.23">RFC4880 - Reason for Revocation</see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-reason-for-revocation">
    /// RFC9580 - Reason for Revocation
    /// </see>
    /// </remarks>
    public class RevocationReason
        : SignatureSubpacket
    {
        public RevocationReason(bool isCritical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.RevocationReason, isCritical, isLongLength, VerifyData(data))
        {
        }

        public RevocationReason(bool isCritical, RevocationReasonTag reason, string description)
            : base(SignatureSubpacketTag.RevocationReason, isCritical, isLongLength: false,
                CreateData(reason, description))
        {
        }

        private static byte[] CreateData(RevocationReasonTag reason, string description)
        {
            byte[] data = Strings.ToUtf8ByteArray(description, preAlloc: 1, postAlloc: 0);
            data[0] = (byte)reason;
            return data;
        }

        // RFC 9580 5.2.3.31: the Reason for Revocation body is 1 octet of revocation code
        // followed by an optional reason string, so at least one octet is required.
        private static byte[] VerifyData(byte[] data)
        {
            if (data.Length < 1)
                throw new ArgumentException("Truncated revocation reason subpacket", nameof(data));

            return data;
        }

        public virtual RevocationReasonTag GetRevocationReason() => (RevocationReasonTag)Data[0];

        public virtual string GetRevocationDescription()
        {
            var data = Data;

            if (data.Length == 1)
                return string.Empty;

            return Strings.FromUtf8ByteArray(data, 1, data.Length - 1);
        }
    }
}
