using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Security
{
    /// <remarks>
    ///  Utility class for creating HMac object from their names/Oids
    /// </remarks>
    public static class MacUtilities
    {
        private static readonly Dictionary<string, string> AlgorithmMap =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, string> AlgorithmOidMap =
            new Dictionary<DerObjectIdentifier, string>();

        static MacUtilities()
        {
            AlgorithmOidMap[IanaObjectIdentifiers.HmacMD5] = "HMAC-MD5";
            AlgorithmOidMap[IanaObjectIdentifiers.HmacRipeMD160] = "HMAC-RIPEMD160";
            AlgorithmOidMap[IanaObjectIdentifiers.HmacSha1] = "HMAC-SHA1";
            AlgorithmOidMap[IanaObjectIdentifiers.HmacTiger] = "HMAC-TIGER";

            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha1] = "HMAC-SHA1";
            AlgorithmOidMap[MiscObjectIdentifiers.HMAC_SHA1] = "HMAC-SHA1";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha224] = "HMAC-SHA224";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha256] = "HMAC-SHA256";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha384] = "HMAC-SHA384";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha512] = "HMAC-SHA512";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha512_224] = "HMAC-SHA512-224";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha512_256] = "HMAC-SHA512-256";

            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_224] = "HMAC-SHA3-224";
            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_256] = "HMAC-SHA3-256";
            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_384] = "HMAC-SHA3-384";
            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_512] = "HMAC-SHA3-512";

            AlgorithmOidMap[RosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_256] = "HMAC-GOST3411-2012-256";
            AlgorithmOidMap[RosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_512] = "HMAC-GOST3411-2012-512";

            // TODO AESMAC?

            AlgorithmMap["DES"] = "DESMAC";
            AlgorithmMap["DES/CFB8"] = "DESMAC/CFB8";
            AlgorithmMap["DES64"] = "DESMAC64";
            AlgorithmMap["DESEDE"] = "DESEDEMAC";
            AlgorithmOidMap[PkcsObjectIdentifiers.DesEde3Cbc] = "DESEDEMAC";
            AlgorithmMap["DESEDE/CFB8"] = "DESEDEMAC/CFB8";
            AlgorithmMap["DESISO9797MAC"] = "DESWITHISO9797";
            AlgorithmMap["DESEDE64"] = "DESEDEMAC64";

            AlgorithmMap["DESEDE64WITHISO7816-4PADDING"] = "DESEDEMAC64WITHISO7816-4PADDING";
            AlgorithmMap["DESEDEISO9797ALG1MACWITHISO7816-4PADDING"] = "DESEDEMAC64WITHISO7816-4PADDING";
            AlgorithmMap["DESEDEISO9797ALG1WITHISO7816-4PADDING"] = "DESEDEMAC64WITHISO7816-4PADDING";

            AlgorithmMap["ISO9797ALG3"] = "ISO9797ALG3MAC";
            AlgorithmMap["ISO9797ALG3MACWITHISO7816-4PADDING"] = "ISO9797ALG3WITHISO7816-4PADDING";

            AlgorithmMap["SKIPJACK"] = "SKIPJACKMAC";
            AlgorithmMap["SKIPJACK/CFB8"] = "SKIPJACKMAC/CFB8";
            AlgorithmMap["IDEA"] = "IDEAMAC";
            AlgorithmMap["IDEA/CFB8"] = "IDEAMAC/CFB8";
            AlgorithmMap["RC2"] = "RC2MAC";
            AlgorithmMap["RC2/CFB8"] = "RC2MAC/CFB8";
            AlgorithmMap["RC5"] = "RC5MAC";
            AlgorithmMap["RC5/CFB8"] = "RC5MAC/CFB8";
            AlgorithmMap["GOST28147"] = "GOST28147MAC";
            AlgorithmMap["VMPC"] = "VMPCMAC";
            AlgorithmMap["VMPC-MAC"] = "VMPCMAC";
            AlgorithmMap["SIPHASH"] = "SIPHASH-2-4";

            AlgorithmMap["PBEWITHHMACSHA"] = "PBEWITHHMACSHA1";
            AlgorithmOidMap[OiwObjectIdentifiers.IdSha1] = "PBEWITHHMACSHA1";

#if DEBUG
            foreach (var key in AlgorithmMap.Keys)
            {
                if (DerObjectIdentifier.TryFromID(key, out var ignore))
                    throw new Exception("OID mapping belongs in AlgorithmOidMap: " + key);
            }

            var mechanisms = new HashSet<string>(AlgorithmMap.Values);
            mechanisms.UnionWith(AlgorithmOidMap.Values);

            foreach (var mechanism in mechanisms)
            {
                if (AlgorithmMap.TryGetValue(mechanism, out var check))
                {
                    if (mechanism != check)
                        throw new Exception("Mechanism mapping MUST be to self: " + mechanism);
                }
                else
                {
                    if (!mechanism.Equals(mechanism.ToUpperInvariant()))
                        throw new Exception("Unmapped mechanism MUST be uppercase: " + mechanism);
                }
            }
#endif
        }

        public static byte[] CalculateMac(string algorithm, ICipherParameters cp, byte[] input)
        {
            IMac mac = GetMac(algorithm);
            mac.Init(cp);
            mac.BlockUpdate(input, 0, input.Length);
            return DoFinal(mac);
        }

        public static byte[] DoFinal(IMac mac)
        {
            byte[] b = new byte[mac.GetMacSize()];
            mac.DoFinal(b, 0);
            return b;
        }

        public static byte[] DoFinal(IMac mac, byte[] input)
        {
            mac.BlockUpdate(input, 0, input.Length);
            return DoFinal(mac);
        }

        public static string GetAlgorithmName(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(AlgorithmOidMap, oid);
        }

        // TODO[api] Change parameter name to 'oid'
        public static IMac GetMac(DerObjectIdentifier id)
        {
            if (id == null)
                throw new ArgumentNullException(nameof(id));

            if (AlgorithmOidMap.TryGetValue(id, out var mechanism))
            {
                var mac = GetMacForMechanism(mechanism);
                if (mac != null)
                    return mac;
            }

            throw new SecurityUtilityException("Mac OID not recognised.");
        }

        public static IMac GetMac(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            string mechanism = GetMechanism(algorithm) ?? algorithm.ToUpperInvariant();

            var mac = GetMacForMechanism(mechanism);
            if (mac != null)
                return mac;

            throw new SecurityUtilityException("Mac " + algorithm + " not recognised.");
        }

        private static IMac GetMacForMechanism(string mechanism)
        {
            if (Platform.StartsWith(mechanism, "PBEWITH"))
            {
                mechanism = mechanism.Substring("PBEWITH".Length);
            }

            if (Platform.StartsWith(mechanism, "HMAC"))
            {
                string digestName;
                if (Platform.StartsWith(mechanism, "HMAC-") || Platform.StartsWith(mechanism, "HMAC/"))
                {
                    digestName = mechanism.Substring(5);
                }
                else
                {
                    digestName = mechanism.Substring(4);
                }

                return new HMac(DigestUtilities.GetDigest(digestName));
            }

            if (mechanism == "AESCMAC")
            {
                return new CMac(AesUtilities.CreateEngine());
            }
            if (mechanism == "DESMAC")
            {
                return new CbcBlockCipherMac(new DesEngine());
            }
            if (mechanism == "DESMAC/CFB8")
            {
                return new CfbBlockCipherMac(new DesEngine());
            }
            if (mechanism == "DESMAC64")
            {
                return new CbcBlockCipherMac(new DesEngine(), 64);
            }
            if (mechanism == "DESEDECMAC")
            {
                return new CMac(new DesEdeEngine());
            }
            if (mechanism == "DESEDEMAC")
            {
                return new CbcBlockCipherMac(new DesEdeEngine());
            }
            if (mechanism == "DESEDEMAC/CFB8")
            {
                return new CfbBlockCipherMac(new DesEdeEngine());
            }
            if (mechanism == "DESEDEMAC64")
            {
                return new CbcBlockCipherMac(new DesEdeEngine(), 64);
            }
            if (mechanism == "DESEDEMAC64WITHISO7816-4PADDING")
            {
                return new CbcBlockCipherMac(new DesEdeEngine(), 64, new ISO7816d4Padding());
            }
            if (mechanism == "DESWITHISO9797"
                || mechanism == "ISO9797ALG3MAC")
            {
                return new ISO9797Alg3Mac(new DesEngine());
            }
            if (mechanism == "ISO9797ALG3WITHISO7816-4PADDING")
            {
                return new ISO9797Alg3Mac(new DesEngine(), new ISO7816d4Padding());
            }
            if (mechanism == "SKIPJACKMAC")
            {
                return new CbcBlockCipherMac(new SkipjackEngine());
            }
            if (mechanism == "SKIPJACKMAC/CFB8")
            {
                return new CfbBlockCipherMac(new SkipjackEngine());
            }
            if (mechanism == "IDEAMAC")
            {
                return new CbcBlockCipherMac(new IdeaEngine());
            }
            if (mechanism == "IDEAMAC/CFB8")
            {
                return new CfbBlockCipherMac(new IdeaEngine());
            }
            if (mechanism == "RC2MAC")
            {
                return new CbcBlockCipherMac(new RC2Engine());
            }
            if (mechanism == "RC2MAC/CFB8")
            {
                return new CfbBlockCipherMac(new RC2Engine());
            }
            if (mechanism == "RC5MAC")
            {
                return new CbcBlockCipherMac(new RC532Engine());
            }
            if (mechanism == "RC5MAC/CFB8")
            {
                return new CfbBlockCipherMac(new RC532Engine());
            }
            if (mechanism == "GOST28147MAC")
            {
                return new Gost28147Mac();
            }
            if (mechanism == "VMPCMAC")
            {
                return new VmpcMac();
            }
            if (mechanism == "SIPHASH-2-4")
            {
                return new SipHash();
            }
            return null;
        }

        private static string GetMechanism(string algorithm)
        {
            if (AlgorithmMap.TryGetValue(algorithm, out var mechanism1))
                return mechanism1;

            if (DerObjectIdentifier.TryFromID(algorithm, out var oid))
            {
                if (AlgorithmOidMap.TryGetValue(oid, out var mechanism2))
                    return mechanism2;
            }

            return null;
        }
    }
}
