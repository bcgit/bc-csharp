namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic tags for symmetric key algorithms
    */
    public enum SymmetricKeyAlgorithmTag
    {
        Null = 0,         // Plaintext or unencrypted data
        Idea = 1,         // IDEA [IDEA]
        TripleDes = 2,    // Triple-DES (DES-EDE, as per spec -168 bit key derived from 192)
        Cast5 = 3,        // Cast5 (128 bit key, as per RFC 2144)
        Blowfish = 4,     // Blowfish (128 bit key, 16 rounds) [Blowfish]
        Safer = 5,        // Reserved - formerly Safer-SK128 (13 rounds) [Safer]
        Des = 6,          // Reserved for DES/SK
        Aes128 = 7,       // AES with 128-bit key
        Aes192 = 8,       // AES with 192-bit key
        Aes256 = 9,       // AES with 256-bit key
        Twofish = 10,     // Twofish with 256-bit key [TWOFISH]
        Camellia128 = 11, // Camellia with 128-bit key [RFC3713]
        Camellia192 = 12, // Camellia with 192-bit key
        Camellia256 = 13, // Camellia with 256-bit key


        Experimental_1 = 100,
        Experimental_2 = 101,
        Experimental_3 = 102,
        Experimental_4 = 103,
        Experimental_5 = 104,
        Experimental_6 = 105,
        Experimental_7 = 106,
        Experimental_8 = 107,
        Experimental_9 = 108,
        Experimental_10 = 109,
        Experimental_11 = 110
    }
}
