using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>
    /// The WOTS+ parameter sets, keyed by the parameters that pick one: RFC 8391 sec. 5.2 and NIST SP 800-208
    /// sec. 5.
    /// </summary>
    internal sealed class WotsPlusOid
        : XmssOid
    {
        /// <summary>WOTS+ OID lookup table.</summary>
        private static readonly Dictionary<string, WotsPlusOid> OidLookupTable = CreateLookupTable();

        private static Dictionary<string, WotsPlusOid> CreateLookupTable()
        {
            var map = new Dictionary<string, WotsPlusOid>();
            // RFC 8391
            Add(map, "SHA-256", 32, 16, 67, 0x01000001, "WOTSP_SHA2-256_W16");
            Add(map, "SHA-512", 64, 16, 131, 0x02000002, "WOTSP_SHA2-512_W16");
            Add(map, "SHAKE128", 32, 16, 67, 0x03000003, "WOTSP_SHAKE128_W16");
            Add(map, "SHAKE256", 64, 16, 131, 0x04000004, "WOTSP_SHAKE256_W16");

            // SP 800-208
            Add(map, "SHA-256", 24, 16, 51, 0x05000005, "WOTSP_SHA2-192_W16");
            Add(map, "SHAKE256-LEN", 32, 16, 67, 0x06000006, "WOTSP_SHAKE256_256_W16");
            Add(map, "SHAKE256-LEN", 24, 16, 51, 0x07000007, "WOTSP_SHAKE256_192_W16");

            return map;
        }

        private static void Add(Dictionary<string, WotsPlusOid> map, string algorithmName, int digestSize,
            int winternitzParameter, int len, int oid, string stringRepresentation)
        {
            map.Add(CreateKey(algorithmName, digestSize, winternitzParameter, len),
                new WotsPlusOid(oid, stringRepresentation));
        }

        private WotsPlusOid(int oid, string stringRepresentation)
            : base(oid, stringRepresentation)
        {
        }

        /// <summary>Lookup OID.</summary>
        /// <param name="algorithmName">Algorithm name.</param>
        /// <param name="digestSize">Digest size n.</param>
        /// <param name="winternitzParameter">Winternitz parameter.</param>
        /// <param name="len">WOTS+ len.</param>
        /// <returns>WOTS+ OID if parameters were found, null else.</returns>
        internal static WotsPlusOid Lookup(string algorithmName, int digestSize, int winternitzParameter, int len)
        {
            if (algorithmName == null)
                throw new ArgumentNullException(nameof(algorithmName));

            string key = CreateKey(algorithmName, digestSize, winternitzParameter, len);
            return OidLookupTable.TryGetValue(key, out var oid) ? oid : null;
        }
    }
}
