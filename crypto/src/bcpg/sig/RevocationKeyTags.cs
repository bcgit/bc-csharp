namespace Org.BouncyCastle.Bcpg
{
    /// <summary>The tags of a revocation key subpacket.</summary>
    public enum RevocationKeyTag
        : byte
    {
        /// <summary>The class bit that must always be set (0x80).</summary>
        ClassDefault = 0x80,
        /// <summary>The class bit marking the revocation key as sensitive (0x40).</summary>
        ClassSensitive = 0x40
    }
}
