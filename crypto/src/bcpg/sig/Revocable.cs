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
        public Revocable(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.Revocable, critical, isLongLength, data)
        {
        }

        public Revocable(bool critical, bool isRevocable)
            : base(SignatureSubpacketTag.Revocable, critical, isLongLength: false,
                Utilities.BooleanToBytes(isRevocable))
        {
        }

        public bool IsRevocable() => Utilities.BooleanFromBytes(Data);
    }
}
