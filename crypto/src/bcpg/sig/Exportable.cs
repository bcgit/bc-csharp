namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket for marking a signature as exportable or non-exportable.</summary>
    /// <remarks>
    /// Non-exportable signatures are not intended to be published.
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.11">
    /// RFC4880 - Exportable Certification
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-exportable-certification">
    /// RFC9580 - Exportable Certification
    /// </see>
    /// </para>
    /// </remarks>
    public class Exportable
        : SignatureSubpacket
    {
        /// <summary>Create a new <see cref="Exportable"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if is long length, false otherwise.</param>
        /// <param name="data">The data.</param>
        public Exportable(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.Exportable, critical, isLongLength, data)
        {
        }

        /// <summary>Create a new <see cref="Exportable"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isExportable">true if is exportable, false otherwise.</param>
        public Exportable(bool critical, bool isExportable)
            : base(SignatureSubpacketTag.Exportable, critical, isLongLength: false,
                Utilities.BooleanToBytes(isExportable))
        {
        }

        /// <summary>Determine whether the signature is exportable.</summary>
        /// <returns>true if it is exportable, false otherwise.</returns>
        public bool IsExportable() => Utilities.BooleanFromBytes(Data);
    }
}
