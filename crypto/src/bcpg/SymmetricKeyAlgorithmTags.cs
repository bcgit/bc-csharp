namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic tags for symmetric key algorithms.</summary>
    public enum SymmetricKeyAlgorithmTag
    {
        Null = 0,         // Plaintext or unencrypted data
        Idea = 1,         // IDEA [IDEA]
        TripleDes = 2,    // Triple-DES (DES-EDE, as per spec -168 bit key derived from 192)
        Cast5 = 3,        // Cast5 (128 bit key, as per RFC 2144)
        Blowfish = 4,     // Blowfish (128 bit key, 16 rounds) [Blowfish]
        Safer = 5,        // Reserved for SAFER-SK128 (13 rounds)
        Des = 6,          // Reserved for DES/SK
        Aes128 = 7,       // AES with 128-bit key
        Aes192 = 8,       // AES with 192-bit key
        Aes256 = 9,       // AES with 256-bit key
        Twofish = 10,     // Twofish with 256-bit key
        Camellia128 = 11, // Camellia with 128-bit key
        Camellia192 = 12, // Camellia with 192-bit key
        Camellia256 = 13  // Camellia with 256-bit key
    }
}
