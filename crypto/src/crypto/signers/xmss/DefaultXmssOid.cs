using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>
    /// The XMSS parameter sets, keyed by the parameters that pick one: RFC 8391 sec. 5.3 and NIST SP 800-208
    /// sec. 5.
    /// </summary>
    internal sealed class DefaultXmssOid
        : XmssOid
    {
        /// <summary>XMSS OID lookup table.</summary>
        private static readonly Dictionary<string, DefaultXmssOid> OidLookupTable = CreateLookupTable();

        private static Dictionary<string, DefaultXmssOid> CreateLookupTable()
        {
            var map = new Dictionary<string, DefaultXmssOid>();
            // RFC 8391
            Add(map, "SHA-256", 32, 16, 67, 10, 0x00000001, "XMSS_SHA2_10_256");
            Add(map, "SHA-256", 32, 16, 67, 16, 0x00000002, "XMSS_SHA2_16_256");
            Add(map, "SHA-256", 32, 16, 67, 20, 0x00000003, "XMSS_SHA2_20_256");
            Add(map, "SHA-512", 64, 16, 131, 10, 0x00000004, "XMSS_SHA2_10_512");
            Add(map, "SHA-512", 64, 16, 131, 16, 0x00000005, "XMSS_SHA2_16_512");
            Add(map, "SHA-512", 64, 16, 131, 20, 0x00000006, "XMSS_SHA2_20_512");
            Add(map, "SHAKE128", 32, 16, 67, 10, 0x00000007, "XMSS_SHAKE_10_256");
            Add(map, "SHAKE128", 32, 16, 67, 16, 0x00000008, "XMSS_SHAKE_16_256");
            Add(map, "SHAKE128", 32, 16, 67, 20, 0x00000009, "XMSS_SHAKE_20_256");
            Add(map, "SHAKE256", 64, 16, 131, 10, 0x0000000a, "XMSS_SHAKE_10_512");
            Add(map, "SHAKE256", 64, 16, 131, 16, 0x0000000b, "XMSS_SHAKE_16_512");
            Add(map, "SHAKE256", 64, 16, 131, 20, 0x0000000c, "XMSS_SHAKE_20_512");

            // SP 800-208: SHA-256/192 (n=24)
            Add(map, "SHA-256", 24, 16, 51, 10, 0x0000000d, "XMSS_SHA2_10_192");
            Add(map, "SHA-256", 24, 16, 51, 16, 0x0000000e, "XMSS_SHA2_16_192");
            Add(map, "SHA-256", 24, 16, 51, 20, 0x0000000f, "XMSS_SHA2_20_192");

            // SP 800-208: SHAKE256/256 (n=32)
            Add(map, "SHAKE256-LEN", 32, 16, 67, 10, 0x00000010, "XMSS_SHAKE256_10_256");
            Add(map, "SHAKE256-LEN", 32, 16, 67, 16, 0x00000011, "XMSS_SHAKE256_16_256");
            Add(map, "SHAKE256-LEN", 32, 16, 67, 20, 0x00000012, "XMSS_SHAKE256_20_256");

            // SP 800-208: SHAKE256/192 (n=24)
            Add(map, "SHAKE256-LEN", 24, 16, 51, 10, 0x00000013, "XMSS_SHAKE256_10_192");
            Add(map, "SHAKE256-LEN", 24, 16, 51, 16, 0x00000014, "XMSS_SHAKE256_16_192");
            Add(map, "SHAKE256-LEN", 24, 16, 51, 20, 0x00000015, "XMSS_SHAKE256_20_192");

            return map;
        }

        private static void Add(Dictionary<string, DefaultXmssOid> map, string algorithmName, int digestSize,
            int winternitzParameter, int len, int height, int oid, string stringRepresentation)
        {
            map.Add(CreateKey(algorithmName, digestSize, winternitzParameter, len, height),
                new DefaultXmssOid(oid, stringRepresentation));
        }

        private DefaultXmssOid(int oid, string stringRepresentation)
            : base(oid, stringRepresentation)
        {
        }

        /// <summary>Lookup OID.</summary>
        /// <param name="algorithmName">Algorithm name.</param>
        /// <param name="digestSize">Digest size n.</param>
        /// <param name="winternitzParameter">Winternitz parameter.</param>
        /// <param name="len">WOTS+ len.</param>
        /// <param name="height">Binary tree height.</param>
        /// <returns>XMSS OID if parameters were found, null else.</returns>
        internal static DefaultXmssOid Lookup(string algorithmName, int digestSize, int winternitzParameter, int len,
            int height)
        {
            if (algorithmName == null)
                throw new ArgumentNullException(nameof(algorithmName));

            string key = CreateKey(algorithmName, digestSize, winternitzParameter, len, height);
            return OidLookupTable.TryGetValue(key, out var oid) ? oid : null;
        }
    }
}
