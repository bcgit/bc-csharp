using System.Collections.Generic;

using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Tsp
{
    /// <summary>Recognised hash algorithms for the time stamp protocol.</summary>
    /// <remarks>Each field holds the dotted-decimal object identifier of the digest algorithm.</remarks>
    public static class TspAlgorithms
    {
        // TODO[api] Change all these to OIDs

        /// <summary>Object identifier of the MD5 digest algorithm.</summary>
        public static readonly string MD5 = PkcsObjectIdentifiers.MD5.Id;

        /// <summary>Object identifier of the SHA-1 digest algorithm.</summary>
        public static readonly string Sha1 = OiwObjectIdentifiers.IdSha1.Id;

        /// <summary>Object identifier of the SHA-224 digest algorithm.</summary>
        public static readonly string Sha224 = NistObjectIdentifiers.IdSha224.Id;
        /// <summary>Object identifier of the SHA-256 digest algorithm.</summary>
        public static readonly string Sha256 = NistObjectIdentifiers.IdSha256.Id;
        /// <summary>Object identifier of the SHA-384 digest algorithm.</summary>
        public static readonly string Sha384 = NistObjectIdentifiers.IdSha384.Id;
        /// <summary>Object identifier of the SHA-512 digest algorithm.</summary>
        public static readonly string Sha512 = NistObjectIdentifiers.IdSha512.Id;

        /// <summary>Object identifier of the SHA3-224 digest algorithm.</summary>
        public static readonly string Sha3_224 = NistObjectIdentifiers.IdSha3_224.Id;
        /// <summary>Object identifier of the SHA3-256 digest algorithm.</summary>
        public static readonly string Sha3_256 = NistObjectIdentifiers.IdSha3_256.Id;
        /// <summary>Object identifier of the SHA3-384 digest algorithm.</summary>
        public static readonly string Sha3_384 = NistObjectIdentifiers.IdSha3_384.Id;
        /// <summary>Object identifier of the SHA3-512 digest algorithm.</summary>
        public static readonly string Sha3_512 = NistObjectIdentifiers.IdSha3_512.Id;

        /// <summary>Object identifier of the RIPEMD-128 digest algorithm.</summary>
        public static readonly string RipeMD128 = TeleTrusTObjectIdentifiers.RipeMD128.Id;
        /// <summary>Object identifier of the RIPEMD-160 digest algorithm.</summary>
        public static readonly string RipeMD160 = TeleTrusTObjectIdentifiers.RipeMD160.Id;
        /// <summary>Object identifier of the RIPEMD-256 digest algorithm.</summary>
        public static readonly string RipeMD256 = TeleTrusTObjectIdentifiers.RipeMD256.Id;

        /// <summary>Object identifier of the GOST R 34.11-94 digest algorithm.</summary>
        public static readonly string Gost3411 = CryptoProObjectIdentifiers.GostR3411.Id;
        /// <summary>Object identifier of the GOST R 34.11-2012 (256-bit) digest algorithm.</summary>
        public static readonly string Gost3411_2012_256 = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.Id;
        /// <summary>Object identifier of the GOST R 34.11-2012 (512-bit) digest algorithm.</summary>
        public static readonly string Gost3411_2012_512 = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.Id;

        /// <summary>Object identifier of the SM3 digest algorithm.</summary>
        public static readonly string SM3 = GMObjectIdentifiers.sm3.Id;

        // TODO[api] Prefer an enumeration method?
        /// <summary>The object identifiers of all the digest algorithms accepted by the time stamp protocol.</summary>
        public static readonly IList<string> Allowed = CollectionUtilities.ReadOnly(new List<string>()
        {
            Gost3411, Gost3411_2012_256, Gost3411_2012_512, MD5, RipeMD128, RipeMD160, RipeMD256, Sha1, Sha224, Sha256,
            Sha384, Sha512, Sha3_224, Sha3_256, Sha3_384, Sha3_512, SM3
        });
    }
}
