using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Represents revocation reason OpenPGP signature sub packet.
    /// </summary>
    public class RevocationReason
        : SignatureSubpacket
    {
        public RevocationReason(bool isCritical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.RevocationReason, isCritical, isLongLength, data)
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
