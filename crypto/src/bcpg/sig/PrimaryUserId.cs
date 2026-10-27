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
        /// <summary>Create a new <see cref="PrimaryUserId"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if the long length form is used, false otherwise.</param>
        /// <param name="data">The data.</param>
        public PrimaryUserId(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.PrimaryUserId, critical, isLongLength, data)
        {
        }

        /// <summary>Create a new <see cref="PrimaryUserId"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isPrimaryUserId">true if is primary user id, false otherwise.</param>
        public PrimaryUserId(bool critical, bool isPrimaryUserId)
            : base(SignatureSubpacketTag.PrimaryUserId, critical, isLongLength: false,
                Utilities.BooleanToBytes(isPrimaryUserId))
        {
        }

        /// <summary>Determine whether the user ID is marked as the primary user ID.</summary>
        /// <returns>true if it is the primary user ID, false otherwise.</returns>
        public bool IsPrimaryUserId() => Utilities.BooleanFromBytes(Data);
    }
}
