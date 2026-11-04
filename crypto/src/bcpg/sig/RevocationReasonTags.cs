namespace Org.BouncyCastle.Bcpg
{
    /// <summary>The reasons for revoking a key or certification.</summary>
    public enum RevocationReasonTag
        : byte
    {
        /// <summary>No reason specified (key revocations or cert revocations).</summary>
        NoReason = 0,                   // No reason specified (key revocations or cert revocations)
        /// <summary>Key is superseded (key revocations).</summary>
        KeySuperseded = 1,              // Key is superseded (key revocations)
        /// <summary>Key material has been compromised (key revocations).</summary>
        KeyCompromised = 2,             // Key material has been compromised (key revocations)
        /// <summary>Key is retired and no longer used (key revocations).</summary>
        KeyRetired = 3,                 // Key is retired and no longer used (key revocations)
        /// <summary>User ID information is no longer valid (cert revocations).</summary>
        UserNoLongerValid = 32,         // User ID information is no longer valid (cert revocations)

        // 100-110 - Private Use
    }
}
