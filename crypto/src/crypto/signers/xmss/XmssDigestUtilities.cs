using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Digests;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    internal static class XmssDigestUtilities
    {
        private static readonly Dictionary<string, DerObjectIdentifier> NameToOid =
            new Dictionary<string, DerObjectIdentifier>();
        private static readonly Dictionary<DerObjectIdentifier, string> OidToName =
            new Dictionary<DerObjectIdentifier, string>();

        static XmssDigestUtilities()
        {
            NameToOid.Add("SHA-256", NistObjectIdentifiers.IdSha256);
            NameToOid.Add("SHA-512", NistObjectIdentifiers.IdSha512);
            NameToOid.Add("SHAKE128", NistObjectIdentifiers.IdShake128);
            NameToOid.Add("SHAKE256", NistObjectIdentifiers.IdShake256);
            NameToOid.Add("SHAKE256-LEN", NistObjectIdentifiers.IdShake256Len);

            OidToName.Add(NistObjectIdentifiers.IdSha256, "SHA-256");
            OidToName.Add(NistObjectIdentifiers.IdSha512, "SHA-512");
            OidToName.Add(NistObjectIdentifiers.IdShake128, "SHAKE128");
            OidToName.Add(NistObjectIdentifiers.IdShake256, "SHAKE256");
            OidToName.Add(NistObjectIdentifiers.IdShake256Len, "SHAKE256-LEN");
        }

        /// <summary>The digest an XMSS parameter set names, by OID.</summary>
        /// <remarks>
        /// Each comparison has the constant on the left, so a null OID reaches the refusal at the bottom, the same
        /// answer <see cref="GetDigestName"/> gives it.
        /// </remarks>
        /// <param name="oid">the tree digest OID.</param>
        /// <returns>a fresh digest for it.</returns>
        /// <exception cref="ArgumentException">if the OID is not one of the five, or is null.</exception>
        internal static IDigest GetDigest(DerObjectIdentifier oid)
        {
            if (NistObjectIdentifiers.IdSha256.Equals(oid))
                return new Sha256Digest();
            if (NistObjectIdentifiers.IdSha512.Equals(oid))
                return new Sha512Digest();
            if (NistObjectIdentifiers.IdShake128.Equals(oid))
                return new ShakeDigest(128);
            if (NistObjectIdentifiers.IdShake256.Equals(oid))
                return new ShakeDigest(256);
            if (NistObjectIdentifiers.IdShake256Len.Equals(oid))
                return new ShakeDigest(256);

            throw new ArgumentException("unrecognized digest OID: " + oid);
        }

        internal static string GetDigestName(DerObjectIdentifier oid)
        {
            if (oid != null && OidToName.TryGetValue(oid, out var name))
                return name;

            throw new ArgumentException("unrecognized digest oid: " + oid);
        }

        internal static DerObjectIdentifier GetDigestOid(string name)
        {
            if (name != null && NameToOid.TryGetValue(name, out var oid))
                return oid;

            throw new ArgumentException("unrecognized digest name: " + name);
        }

        /// <summary>The output size of the digest an XMSS parameter set names, by OID.</summary>
        /// <exception cref="ArgumentException">if the OID is not one of the five, or is null.</exception>
        internal static int GetDigestSize(DerObjectIdentifier oid) => GetDigest(oid).GetDigestSize();
    }
}
