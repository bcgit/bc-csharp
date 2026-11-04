namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic PGP signature subpacket tag types.</summary>
    public enum SignatureSubpacketTag
    {
        /// <summary>Signature creation time.</summary>
        CreationTime = 2, // signature creation time
        /// <summary>Signature expiration time.</summary>
        ExpireTime = 3, // signature expiration time
        /// <summary>Exportable certification.</summary>
        Exportable = 4, // exportable certification
        /// <summary>Trust signature.</summary>
        TrustSig = 5, // trust signature
        /// <summary>Regular expression.</summary>
        RegExp = 6, // regular expression
        /// <summary>Revocable.</summary>
        Revocable = 7, // revocable
        /// <summary>Key expiration time.</summary>
        KeyExpireTime = 9, // key expiration time
        /// <summary>Placeholder for backward compatibility.</summary>
        Placeholder = 10, // placeholder for backward compatibility
        /// <summary>Preferred symmetric algorithms.</summary>
        PreferredSymmetricAlgorithms = 11, // preferred symmetric algorithms
        /// <summary>Revocation key.</summary>
        RevocationKey = 12, // revocation key
        /// <summary>Issuer key ID.</summary>
        IssuerKeyId = 16, // issuer key ID
        /// <summary>Notation data.</summary>
        NotationData = 20, // notation data
        /// <summary>Preferred hash algorithms.</summary>
        PreferredHashAlgorithms = 21, // preferred hash algorithms
        /// <summary>Preferred compression algorithms.</summary>
        PreferredCompressionAlgorithms = 22, // preferred compression algorithms
        /// <summary>Key server preferences.</summary>
        KeyServerPreferences = 23, // key server preferences
        /// <summary>Preferred key server.</summary>
        PreferredKeyServer = 24, // preferred key server
        /// <summary>Primary user id.</summary>
        PrimaryUserId = 25, // primary user id
        /// <summary>Policy URL.</summary>
        PolicyUrl = 26, // policy URL
        /// <summary>Key flags.</summary>
        KeyFlags = 27, // key flags
        /// <summary>Signer's user id.</summary>
        SignerUserId = 28, // signer's user id
        /// <summary>Reason for revocation.</summary>
        RevocationReason = 29,                  // reason for revocation
        /// <summary>Features.</summary>
        Features = 30,                          // features
        /// <summary>Signature target.</summary>
        SignatureTarget = 31,                   // signature target
        /// <summary>Embedded signature.</summary>
        EmbeddedSignature = 32, // embedded signature
        /// <summary>Issuer key fingerprint.</summary>
        IssuerFingerprint = 33,                 // issuer key fingerprint
        //PreferredAeadAlgorithms = 34,         // RESERVED since crypto-refresh-05
        /// <summary>Intended recipient fingerprint.</summary>
        IntendedRecipientFingerprint = 35,      // intended recipient fingerprint
        /// <summary>Attested certifications (RESERVED).</summary>
        AttestedCertifications = 37,            // attested certifications (RESERVED)
        /// <summary>Key Block (RESERVED).</summary>
        KeyBlock = 38,                          // Key Block (RESERVED)
        /// <summary>Preferred AEAD algorithms.</summary>
        PreferredAeadAlgorithms = 39,           // preferred AEAD algorithms
    }
}
