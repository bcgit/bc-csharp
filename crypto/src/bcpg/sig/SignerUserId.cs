using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>
    /// Signature Subpacket containing the User ID of the identity as which the issuer created the signature.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.22">
    /// RFC4880 - Signer's User ID
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-signers-user-id">
    /// RFC9580 - Signer's User ID
    /// </see>
    /// </remarks>
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

        public string GetId() => Strings.FromUtf8ByteArray(Data);

        public byte[] GetRawId() => GetData();
    }
}
