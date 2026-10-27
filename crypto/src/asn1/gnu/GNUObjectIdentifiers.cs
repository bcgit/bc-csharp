using System;

namespace Org.BouncyCastle.Asn1.Gnu
{
    /// <summary>Object identifiers for the GNU project.</summary>
    // TODO[api] Make static
    public abstract class GnuObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.1</c>.</summary>
        public static readonly DerObjectIdentifier Gnu = new DerObjectIdentifier("1.3.6.1.4.1.11591.1"); // GNU Radius
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.2</c>.</summary>
        public static readonly DerObjectIdentifier GnuPG = new DerObjectIdentifier("1.3.6.1.4.1.11591.2"); // GnuPG (Ägypten)
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.2.1</c>.</summary>
        public static readonly DerObjectIdentifier Notation = new DerObjectIdentifier("1.3.6.1.4.1.11591.2.1"); // notation
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.2.1.1</c>.</summary>
        public static readonly DerObjectIdentifier PkaAddress = new DerObjectIdentifier("1.3.6.1.4.1.11591.2.1.1"); // pkaAddress
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.3</c>.</summary>
        public static readonly DerObjectIdentifier GnuRadar = new DerObjectIdentifier("1.3.6.1.4.1.11591.3"); // GNU Radar
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.12</c>.</summary>
        public static readonly DerObjectIdentifier DigestAlgorithm = new DerObjectIdentifier("1.3.6.1.4.1.11591.12"); // digestAlgorithm
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.12.2</c>.</summary>
        public static readonly DerObjectIdentifier Tiger192 = new DerObjectIdentifier("1.3.6.1.4.1.11591.12.2"); // TIGER/192
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13</c>.</summary>
        public static readonly DerObjectIdentifier EncryptionAlgorithm = new DerObjectIdentifier("1.3.6.1.4.1.11591.13"); // encryptionAlgorithm
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2</c>.</summary>
        public static readonly DerObjectIdentifier Serpent = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2"); // Serpent
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.1</c>.</summary>
        public static readonly DerObjectIdentifier Serpent128Ecb = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.1"); // Serpent-128-ECB
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.2</c>.</summary>
        public static readonly DerObjectIdentifier Serpent128Cbc = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.2"); // Serpent-128-CBC
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.3</c>.</summary>
        public static readonly DerObjectIdentifier Serpent128Ofb = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.3"); // Serpent-128-OFB
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.4</c>.</summary>
        public static readonly DerObjectIdentifier Serpent128Cfb = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.4"); // Serpent-128-CFB
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.21</c>.</summary>
        public static readonly DerObjectIdentifier Serpent192Ecb = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.21"); // Serpent-192-ECB
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.22</c>.</summary>
        public static readonly DerObjectIdentifier Serpent192Cbc = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.22"); // Serpent-192-CBC
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.23</c>.</summary>
        public static readonly DerObjectIdentifier Serpent192Ofb = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.23"); // Serpent-192-OFB
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.24</c>.</summary>
        public static readonly DerObjectIdentifier Serpent192Cfb = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.24"); // Serpent-192-CFB
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.41</c>.</summary>
        public static readonly DerObjectIdentifier Serpent256Ecb = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.41"); // Serpent-256-ECB
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.42</c>.</summary>
        public static readonly DerObjectIdentifier Serpent256Cbc = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.42"); // Serpent-256-CBC
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.43</c>.</summary>
        public static readonly DerObjectIdentifier Serpent256Ofb = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.43"); // Serpent-256-OFB
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.13.2.44</c>.</summary>
        public static readonly DerObjectIdentifier Serpent256Cfb = new DerObjectIdentifier("1.3.6.1.4.1.11591.13.2.44"); // Serpent-256-CFB
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.14</c>.</summary>
        public static readonly DerObjectIdentifier Crc = new DerObjectIdentifier("1.3.6.1.4.1.11591.14"); // CRC algorithms
        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.14.1</c>.</summary>
        public static readonly DerObjectIdentifier Crc32 = new DerObjectIdentifier("1.3.6.1.4.1.11591.14.1"); // CRC 32

        /** 1.3.6.1.4.1.11591.15 - ellipticCurve */
        public static readonly DerObjectIdentifier EllipticCurve = new DerObjectIdentifier("1.3.6.1.4.1.11591.15");

        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.15.1</c>.</summary>
        public static readonly DerObjectIdentifier Ed25519   = EllipticCurve.Branch("1");
    }
}
