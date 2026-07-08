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
        public Exportable(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.Exportable, critical, isLongLength, data)
        {
        }

        public Exportable(bool critical, bool isExportable)
            : base(SignatureSubpacketTag.Exportable, critical, isLongLength: false,
                Utilities.BooleanToBytes(isExportable))
        {
        }

        public bool IsExportable() => Utilities.BooleanFromBytes(Data);
    }
}
