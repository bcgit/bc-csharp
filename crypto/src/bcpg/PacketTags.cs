namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic PGP packet tag types.</remarks>
    public enum PacketTag
    {
        /// <summary>Reserved - a packet tag must not have this value.</summary>
        Reserved = 0,                               //  Reserved - a packet tag must not have this value
        /// <summary>Public-Key Encrypted Session Key Packet.</summary>
        PublicKeyEncryptedSession = 1,              // Public-Key Encrypted Session Key Packet
        /// <summary>Signature Packet.</summary>
        Signature = 2,                              // Signature Packet
        /// <summary>Symmetric-Key Encrypted Session Key Packet.</summary>
        SymmetricKeyEncryptedSessionKey = 3,        // Symmetric-Key Encrypted Session Key Packet
        /// <summary>One-Pass Signature Packet.</summary>
        OnePassSignature = 4,                       // One-Pass Signature Packet
        /// <summary>Secret Key Packet.</summary>
        SecretKey = 5,                              // Secret Key Packet
        /// <summary>Public Key Packet.</summary>
        PublicKey = 6,                              // Public Key Packet
        /// <summary>Secret Subkey Packet.</summary>
        SecretSubkey = 7,                           // Secret Subkey Packet
        /// <summary>Compressed Data Packet.</summary>
        CompressedData = 8,                         // Compressed Data Packet
        /// <summary>Symmetrically Encrypted Data Packet.</summary>
        SymmetricKeyEncrypted = 9,                  // Symmetrically Encrypted Data Packet
        /// <summary>Marker Packet.</summary>
        Marker = 10,                                // Marker Packet
        /// <summary>Literal Data Packet.</summary>
        LiteralData = 11,                           // Literal Data Packet
        /// <summary>Trust Packet.</summary>
        Trust = 12,                                 // Trust Packet
        /// <summary>User ID Packet.</summary>
        UserId = 13,                                // User ID Packet
        /// <summary>Public Subkey Packet.</summary>
        PublicSubkey = 14,                          // Public Subkey Packet
        /// <summary>User attribute.</summary>
        UserAttribute = 17,                         // User attribute
        /// <summary>Symmetric encrypted, integrity protected.</summary>
        SymmetricEncryptedIntegrityProtected = 18,  // Symmetric encrypted, integrity protected
        /// <summary>Modification detection code.</summary>
        ModificationDetectionCode = 19,             // Modification detection code
        /// <summary>AEAD Encrypted Data (seems deprecated).</summary>
        AeadEncData = 20,                           // AEAD Encrypted Data (seems deprecated)
        /// <summary>Padding Packet.</summary>
        Padding = 21,                               // Padding Packet

        /// <summary>Private or Experimental Values.</summary>
        Experimental1 = 60,                         // Private or Experimental Values
        /// <summary>A private or experimental packet tag.</summary>
        Experimental2 = 61,
        /// <summary>A private or experimental packet tag.</summary>
        Experimental3 = 62,
        /// <summary>A private or experimental packet tag.</summary>
        Experimental4 = 63
    }
}
