namespace Org.BouncyCastle.Bcpg
{
    /// <summary>OpenPGP Packet Header Length Format.</summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-headers">OpenPGP Packet Headers</see>
    /// </remarks>
    public enum PacketFormat
    {
        /// <summary>Always use the old (legacy) packet format.</summary>
        Legacy,

        /// <summary>Always use the current (new) packet format.</summary>
        Current,

        /// <summary>Let the individual packet decide the format.</summary>
        /// <remarks>
        /// This allows to round-trip packets without changing the packet format.
        /// <see cref="Packet.HasNewPacketFormat"/>
        /// </remarks>
        Roundtrip,
    }
}
