using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
     * packet giving the User ID of the signer.
     */
    public class SignerUserId
        : SignatureSubpacket
    {
        public SignerUserId(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.SignerUserId, critical, isLongLength, data)
        {
        }

        public SignerUserId(bool critical, string userId)
            : base(SignatureSubpacketTag.SignerUserId, critical, isLongLength: false, Strings.ToUtf8ByteArray(userId))
        {
        }

        public string GetId() => Strings.FromUtf8ByteArray(data);

        public byte[] GetRawId() => Arrays.Clone(data);
    }
}
