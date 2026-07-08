namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket marking a User ID as primary.</summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.19">
    /// RFC4880 - Primary User ID
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-primary-user-id">
    /// RFC9580 - Primary User ID
    /// </see>
    /// </remarks>
    public class PrimaryUserId
        : SignatureSubpacket
    {
        public PrimaryUserId(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.PrimaryUserId, critical, isLongLength, data)
        {
        }

        public PrimaryUserId(bool critical, bool isPrimaryUserId)
            : base(SignatureSubpacketTag.PrimaryUserId, critical, isLongLength: false,
                Utilities.BooleanToBytes(isPrimaryUserId))
        {
        }

        public bool IsPrimaryUserId() => Utilities.BooleanFromBytes(Data);
    }
}
