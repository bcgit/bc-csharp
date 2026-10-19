namespace Org.BouncyCastle.Bcpg
{
    /// <summary>The tags of a revocation key subpacket.</summary>
    public enum RevocationKeyTag
        : byte
    {
        ClassDefault = 0x80,
        ClassSensitive = 0x40
    }
}
