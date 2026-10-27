namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket marking a signature as non-revocable.</summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.12">
    /// RFC4880 - Revocable
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-revocable">
    /// RFC9580 - Revocable
    /// </see>
    /// </remarks>
    public class Revocable
        : SignatureSubpacket
    {
        /// <summary>Create a new <see cref="Revocable"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if the long length form is used, false otherwise.</param>
        /// <param name="data">The data.</param>
        public Revocable(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.Revocable, critical, isLongLength, data)
        {
        }

        /// <summary>Create a new <see cref="Revocable"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isRevocable">true if is revocable, false otherwise.</param>
        public Revocable(bool critical, bool isRevocable)
            : base(SignatureSubpacketTag.Revocable, critical, isLongLength: false,
                Utilities.BooleanToBytes(isRevocable))
        {
        }

        /// <summary>Determine whether the signature is revocable.</summary>
        /// <returns>true if it is revocable, false otherwise.</returns>
        public bool IsRevocable() => Utilities.BooleanFromBytes(Data);
    }
}
