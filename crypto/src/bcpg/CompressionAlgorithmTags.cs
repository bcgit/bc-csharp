namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic tags for compression algorithms.</remarks>
    public enum CompressionAlgorithmTag
    {
        /// <summary>Uncompressed.</summary>
        Uncompressed = 0, // Uncompressed
        /// <summary>ZIP (RFC 1951).</summary>
        Zip = 1, // ZIP (RFC 1951)
        /// <summary>ZLIB (RFC 1950).</summary>
        ZLib = 2, // ZLIB (RFC 1950)
        /// <summary>BZ2.</summary>
        BZip2 = 3, // BZ2
    }
}
