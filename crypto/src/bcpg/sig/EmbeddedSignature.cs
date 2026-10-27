using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket for embedding one Signature into another.</summary>
    /// <remarks>
    /// This packet is used e.g. for embedding a primary-key binding signature
    /// (<see cref="PgpSignature.PrimaryKeyBinding"/>) into a subkey-binding signature
    /// (<see cref="PgpSignature.SubkeyBinding"/>) for a signing-capable subkey.
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.26">
    /// RFC4880 - Embedded Signature
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-embedded-signature">
    /// RFC9580 - Embedded Signature
    /// </see>
    /// </para>
    /// </remarks>
    public class EmbeddedSignature
        : SignatureSubpacket
    {
        /// <summary>Create a new <see cref="EmbeddedSignature"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if the long length form is used, false otherwise.</param>
        /// <param name="data">The data.</param>
        public EmbeddedSignature(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.EmbeddedSignature, critical, isLongLength, data)
        {
        }
    }
}
