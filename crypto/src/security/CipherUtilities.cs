using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Nsri;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Security
{
    /// <remarks>
    ///  Cipher Utility class contains methods that can not be specifically grouped into other classes.
    /// </remarks>
    public static class CipherUtilities
    {
        private enum CipherAlgorithm {
            AES,
            ARC4,
            ARIA,
            BLOWFISH,
            CAMELLIA,
            CAST5,
            CAST6,
            CHACHA,
            CHACHA20_POLY1305,
            CHACHA7539,
            DES,
            DESEDE,
            ELGAMAL,
            GOST28147,
            HC128,
            HC256,
            IDEA,
            NOEKEON,
            PBEWITHSHAAND128BITRC4,
            PBEWITHSHAAND40BITRC4,
            RC2,
            RC5,
            RC5_64,
            RC6,
            RIJNDAEL,
            RSA,
            SALSA20,
            SEED,
            SERPENT,
            SKIPJACK,
            SM4,
            TEA,
            THREEFISH_256,
            THREEFISH_512,
            THREEFISH_1024,
            TNEPRES,
            TWOFISH,
            VMPC,
            VMPC_KSA3,
            XTEA,
            LIBSECUREXTEA
        };

        private enum CipherMode { ECB, NONE, CBC, CCM, CFB, CTR, CTS, EAX, GCM, GOFB, OCB, OFB, OPENPGPCFB, SIC };
        private enum CipherPadding
        {
            NOPADDING,
            RAW,
            ISO10126PADDING,
            ISO10126D2PADDING,
            ISO10126_2PADDING,
            ISO7816_4PADDING,
            ISO9797_1PADDING,
            ISO9796_1,
            ISO9796_1PADDING,
            OAEP,
            OAEPPADDING,
            OAEPWITHMD5ANDMGF1PADDING,
            OAEPWITHSHA1ANDMGF1PADDING,
            OAEPWITHSHA_1ANDMGF1PADDING,
            OAEPWITHSHA224ANDMGF1PADDING,
            OAEPWITHSHA_224ANDMGF1PADDING,
            OAEPWITHSHA256ANDMGF1PADDING,
            OAEPWITHSHA_256ANDMGF1PADDING,
            OAEPWITHSHA256ANDMGF1WITHSHA256PADDING,
            OAEPWITHSHA_256ANDMGF1WITHSHA_256PADDING,
            OAEPWITHSHA256ANDMGF1WITHSHA1PADDING,
            OAEPWITHSHA_256ANDMGF1WITHSHA_1PADDING,
            OAEPWITHSHA384ANDMGF1PADDING,
            OAEPWITHSHA_384ANDMGF1PADDING,
            OAEPWITHSHA512ANDMGF1PADDING,
            OAEPWITHSHA_512ANDMGF1PADDING,
            PKCS1,
            PKCS1PADDING,
            PKCS5,
            PKCS5PADDING,
            PKCS7,
            PKCS7PADDING,
            TBCPADDING,
            WITHCTS,
            X923PADDING,
            ZEROBYTEPADDING,
        };

        private static readonly Dictionary<string, string> AlgorithmMap =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, string> AlgorithmOidMap =
            new Dictionary<DerObjectIdentifier, string>();

        static CipherUtilities()
        {
            // Signal to obfuscation tools not to change enum constants
            Enums.GetArbitraryValue<CipherAlgorithm>().ToString();
            Enums.GetArbitraryValue<CipherMode>().ToString();
            Enums.GetArbitraryValue<CipherPadding>().ToString();

            // TODO Flesh out the list of aliases

            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Cbc] = "AES/CBC/PKCS7PADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Cbc] = "AES/CBC/PKCS7PADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Cbc] = "AES/CBC/PKCS7PADDING";

            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Ccm] = "AES/CCM/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Ccm] = "AES/CCM/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Ccm] = "AES/CCM/NOPADDING";

            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Cfb] = "AES/CFB/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Cfb] = "AES/CFB/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Cfb] = "AES/CFB/NOPADDING";

            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Ecb] = "AES/ECB/PKCS7PADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Ecb] = "AES/ECB/PKCS7PADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Ecb] = "AES/ECB/PKCS7PADDING";
            AlgorithmMap["AES//PKCS7"] = "AES/ECB/PKCS7PADDING";
            AlgorithmMap["AES//PKCS7PADDING"] = "AES/ECB/PKCS7PADDING";
            AlgorithmMap["AES//PKCS5"] = "AES/ECB/PKCS7PADDING";
            AlgorithmMap["AES//PKCS5PADDING"] = "AES/ECB/PKCS7PADDING";

            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Gcm] = "AES/GCM/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Gcm] = "AES/GCM/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Gcm] = "AES/GCM/NOPADDING";

            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Ofb] = "AES/OFB/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Ofb] = "AES/OFB/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Ofb] = "AES/OFB/NOPADDING";

            AlgorithmOidMap[NsriObjectIdentifiers.id_aria128_cbc] = "ARIA/CBC/PKCS7PADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria192_cbc] = "ARIA/CBC/PKCS7PADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria256_cbc] = "ARIA/CBC/PKCS7PADDING";

            AlgorithmOidMap[NsriObjectIdentifiers.id_aria128_ccm] = "ARIA/CCM/NOPADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria192_ccm] = "ARIA/CCM/NOPADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria256_ccm] = "ARIA/CCM/NOPADDING";

            AlgorithmOidMap[NsriObjectIdentifiers.id_aria128_cfb] = "ARIA/CFB/NOPADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria192_cfb] = "ARIA/CFB/NOPADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria256_cfb] = "ARIA/CFB/NOPADDING";

            AlgorithmOidMap[NsriObjectIdentifiers.id_aria128_ctr] = "ARIA/CTR/NOPADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria192_ctr] = "ARIA/CTR/NOPADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria256_ctr] = "ARIA/CTR/NOPADDING";

            AlgorithmOidMap[NsriObjectIdentifiers.id_aria128_ecb] = "ARIA/ECB/PKCS7PADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria192_ecb] = "ARIA/ECB/PKCS7PADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria256_ecb] = "ARIA/ECB/PKCS7PADDING";
            AlgorithmMap["ARIA//PKCS7"] = "ARIA/ECB/PKCS7PADDING";
            AlgorithmMap["ARIA//PKCS7PADDING"] = "ARIA/ECB/PKCS7PADDING";
            AlgorithmMap["ARIA//PKCS5"] = "ARIA/ECB/PKCS7PADDING";
            AlgorithmMap["ARIA//PKCS5PADDING"] = "ARIA/ECB/PKCS7PADDING";

            AlgorithmOidMap[NsriObjectIdentifiers.id_aria128_gcm] = "ARIA/GCM/NOPADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria192_gcm] = "ARIA/GCM/NOPADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria256_gcm] = "ARIA/GCM/NOPADDING";

            AlgorithmOidMap[NsriObjectIdentifiers.id_aria128_ofb] = "ARIA/OFB/NOPADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria192_ofb] = "ARIA/OFB/NOPADDING";
            AlgorithmOidMap[NsriObjectIdentifiers.id_aria256_ofb] = "ARIA/OFB/NOPADDING";

            AlgorithmMap["RSA/ECB/PKCS1"] = "RSA//PKCS1PADDING";
            AlgorithmMap["RSA/ECB/PKCS1PADDING"] = "RSA//PKCS1PADDING";
            AlgorithmOidMap[PkcsObjectIdentifiers.RsaEncryption] = "RSA//PKCS1PADDING";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdRsaesOaep] = "RSA//OAEPPADDING";

            AlgorithmOidMap[OiwObjectIdentifiers.DesCbc] = "DES/CBC";
            AlgorithmOidMap[OiwObjectIdentifiers.DesCfb] = "DES/CFB";
            AlgorithmOidMap[OiwObjectIdentifiers.DesEcb] = "DES/ECB";
            AlgorithmOidMap[OiwObjectIdentifiers.DesOfb] = "DES/OFB";
            AlgorithmOidMap[OiwObjectIdentifiers.DesEde] = "DESEDE";
            AlgorithmMap["TDEA"] = "DESEDE";
            AlgorithmOidMap[PkcsObjectIdentifiers.DesEde3Cbc] = "DESEDE/CBC";
            AlgorithmOidMap[PkcsObjectIdentifiers.RC2Cbc] = "RC2/CBC";
            AlgorithmOidMap[MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC] = "IDEA/CBC";
            AlgorithmOidMap[MiscObjectIdentifiers.cast5CBC] = "CAST5/CBC";

            AlgorithmMap["RC4"] = "ARC4";
            AlgorithmMap["ARCFOUR"] = "ARC4";
            AlgorithmOidMap[PkcsObjectIdentifiers.rc4] = "ARC4";



            AlgorithmMap["PBEWITHSHA1AND128BITRC4"] = "PBEWITHSHAAND128BITRC4";
            AlgorithmOidMap[PkcsObjectIdentifiers.PbeWithShaAnd128BitRC4] = "PBEWITHSHAAND128BITRC4";
            AlgorithmMap["PBEWITHSHA1AND40BITRC4"] = "PBEWITHSHAAND40BITRC4";
            AlgorithmOidMap[PkcsObjectIdentifiers.PbeWithShaAnd40BitRC4] = "PBEWITHSHAAND40BITRC4";

            AlgorithmMap["PBEWITHSHA1ANDDES"] = "PBEWITHSHA1ANDDES-CBC";
            AlgorithmOidMap[PkcsObjectIdentifiers.PbeWithSha1AndDesCbc] = "PBEWITHSHA1ANDDES-CBC";
            AlgorithmMap["PBEWITHSHA1ANDRC2"] = "PBEWITHSHA1ANDRC2-CBC";
            AlgorithmOidMap[PkcsObjectIdentifiers.PbeWithSha1AndRC2Cbc] = "PBEWITHSHA1ANDRC2-CBC";

            AlgorithmMap["PBEWITHSHA1AND3-KEYTRIPLEDES-CBC"] = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";
            AlgorithmMap["PBEWITHSHAAND3KEYTRIPLEDES"] = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";
            AlgorithmOidMap[PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc] = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";
            AlgorithmMap["PBEWITHSHA1ANDDESEDE"] = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";

            AlgorithmMap["PBEWITHSHA1AND2-KEYTRIPLEDES-CBC"] = "PBEWITHSHAAND2-KEYTRIPLEDES-CBC";
            AlgorithmOidMap[PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc] = "PBEWITHSHAAND2-KEYTRIPLEDES-CBC";

            AlgorithmMap["PBEWITHSHA1AND128BITRC2-CBC"] = "PBEWITHSHAAND128BITRC2-CBC";
            AlgorithmOidMap[PkcsObjectIdentifiers.PbeWithShaAnd128BitRC2Cbc] = "PBEWITHSHAAND128BITRC2-CBC";

            AlgorithmMap["PBEWITHSHA1AND40BITRC2-CBC"] = "PBEWITHSHAAND40BITRC2-CBC";
            AlgorithmOidMap[PkcsObjectIdentifiers.PbewithShaAnd40BitRC2Cbc] = "PBEWITHSHAAND40BITRC2-CBC";

            AlgorithmMap["PBEWITHSHA1AND128BITAES-CBC-BC"] = "PBEWITHSHAAND128BITAES-CBC-BC";
            AlgorithmMap["PBEWITHSHA-1AND128BITAES-CBC-BC"] = "PBEWITHSHAAND128BITAES-CBC-BC";

            AlgorithmMap["PBEWITHSHA1AND192BITAES-CBC-BC"] = "PBEWITHSHAAND192BITAES-CBC-BC";
            AlgorithmMap["PBEWITHSHA-1AND192BITAES-CBC-BC"] = "PBEWITHSHAAND192BITAES-CBC-BC";

            AlgorithmMap["PBEWITHSHA1AND256BITAES-CBC-BC"] = "PBEWITHSHAAND256BITAES-CBC-BC";
            AlgorithmMap["PBEWITHSHA-1AND256BITAES-CBC-BC"] = "PBEWITHSHAAND256BITAES-CBC-BC";

            AlgorithmMap["PBEWITHSHA-256AND128BITAES-CBC-BC"] = "PBEWITHSHA256AND128BITAES-CBC-BC";
            AlgorithmMap["PBEWITHSHA-256AND192BITAES-CBC-BC"] = "PBEWITHSHA256AND192BITAES-CBC-BC";
            AlgorithmMap["PBEWITHSHA-256AND256BITAES-CBC-BC"] = "PBEWITHSHA256AND256BITAES-CBC-BC";


            AlgorithmMap["GOST"] = "GOST28147";
            AlgorithmMap["GOST-28147"] = "GOST28147";
            AlgorithmOidMap[CryptoProObjectIdentifiers.GostR28147Gcfb] = "GOST28147/CBC/PKCS7PADDING";

            AlgorithmMap["RC5-32"] = "RC5";

            AlgorithmOidMap[NttObjectIdentifiers.IdCamellia128Cbc] = "CAMELLIA/CBC/PKCS7PADDING";
            AlgorithmOidMap[NttObjectIdentifiers.IdCamellia192Cbc] = "CAMELLIA/CBC/PKCS7PADDING";
            AlgorithmOidMap[NttObjectIdentifiers.IdCamellia256Cbc] = "CAMELLIA/CBC/PKCS7PADDING";

            AlgorithmOidMap[KisaObjectIdentifiers.IdSeedCbc] = "SEED/CBC/PKCS7PADDING";

            /*
             * TODO[api] Incorrect version of cryptlib_algorithm_blowfish_CBC
             * Remove at major version update and delete bad test data "pbes2.bf-cbc.key"
             */
            AlgorithmOidMap[new DerObjectIdentifier("1.3.6.1.4.1.3029.1.2")] = "BLOWFISH/CBC";
            AlgorithmOidMap[MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC] = "BLOWFISH/CBC";

            AlgorithmMap["CHACHA20"] = "CHACHA7539";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdAlgAeadChaCha20Poly1305] = "CHACHA20-POLY1305";

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

        public static string GetAlgorithmName(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(AlgorithmOidMap, oid);
        }

        public static IBufferedCipher GetCipher(DerObjectIdentifier oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (AlgorithmOidMap.TryGetValue(oid, out var mechanism))
            {
                var cipher = GetCipherForMechanism(mechanism);
                if (cipher != null)
                    return cipher;
            }

            throw new SecurityUtilityException("Cipher OID not recognised.");
        }

        public static IBufferedCipher GetCipher(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            string mechanism = GetMechanism(algorithm) ?? algorithm.ToUpperInvariant();

            var cipher = GetCipherForMechanism(mechanism);
            if (cipher != null)
                return cipher;

            throw new SecurityUtilityException("Cipher " + algorithm + " not recognised.");
        }

        private static IBufferedCipher GetCipherForMechanism(string mechanism)
        {
            IBasicAgreement iesAgreement = null;
            if (mechanism == "IES")
            {
                iesAgreement = new DHBasicAgreement();
            }
            else if (mechanism == "ECIES")
            {
                iesAgreement = new ECDHBasicAgreement();
            }

            if (iesAgreement != null)
            {
                return new BufferedIesCipher(
                    new IesEngine(
                    iesAgreement,
                    new Kdf2BytesGenerator(
                    new Sha1Digest()),
                    new HMac(
                    new Sha1Digest())));
            }



            if (Platform.StartsWith(mechanism, "PBE"))
            {
                if (Platform.EndsWith(mechanism, "-CBC"))
                {
                    if (mechanism == "PBEWITHSHA1ANDDES-CBC")
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(new DesEngine()));
                    }
                    else if (mechanism == "PBEWITHSHA1ANDRC2-CBC")
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(new RC2Engine()));
                    }
                    else if (Strings.IsOneOf(mechanism,
                        "PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC"))
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(new DesEdeEngine()));
                    }
                    else if (Strings.IsOneOf(mechanism,
                        "PBEWITHSHAAND128BITRC2-CBC", "PBEWITHSHAAND40BITRC2-CBC"))
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(new RC2Engine()));
                    }
                }
                else if (Platform.EndsWith(mechanism, "-BC") || Platform.EndsWith(mechanism, "-OPENSSL"))
                {
                    if (Strings.IsOneOf(mechanism,
                        "PBEWITHSHAAND128BITAES-CBC-BC",
                        "PBEWITHSHAAND192BITAES-CBC-BC",
                        "PBEWITHSHAAND256BITAES-CBC-BC",
                        "PBEWITHSHA256AND128BITAES-CBC-BC",
                        "PBEWITHSHA256AND192BITAES-CBC-BC",
                        "PBEWITHSHA256AND256BITAES-CBC-BC",
                        "PBEWITHMD5AND128BITAES-CBC-OPENSSL",
                        "PBEWITHMD5AND192BITAES-CBC-OPENSSL",
                        "PBEWITHMD5AND256BITAES-CBC-OPENSSL"))
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(AesUtilities.CreateEngine()));
                    }
                }
            }



            string[] parts = mechanism.Split('/');

            IAeadCipher aeadCipher = null;
            IBlockCipher blockCipher = null;
            IAsymmetricBlockCipher asymBlockCipher = null;
            IStreamCipher streamCipher = null;

            string algorithmName = CollectionUtilities.GetValueOrKey(AlgorithmMap, parts[0]).ToUpperInvariant();

            CipherAlgorithm cipherAlgorithm;
            try
            {
                cipherAlgorithm = Enums.GetEnumValue<CipherAlgorithm>(algorithmName);
            }
            catch (ArgumentException)
            {
                return null;
            }

            switch (cipherAlgorithm)
            {
            case CipherAlgorithm.AES:
                blockCipher = AesUtilities.CreateEngine();
                break;
            case CipherAlgorithm.ARC4:
                streamCipher = new RC4Engine();
                break;
            case CipherAlgorithm.ARIA:
                blockCipher = new AriaEngine();
                break;
            case CipherAlgorithm.BLOWFISH:
                blockCipher = new BlowfishEngine();
                break;
            case CipherAlgorithm.CAMELLIA:
                blockCipher = new CamelliaEngine();
                break;
            case CipherAlgorithm.CAST5:
                blockCipher = new Cast5Engine();
                break;
            case CipherAlgorithm.CAST6:
                blockCipher = new Cast6Engine();
                break;
            case CipherAlgorithm.CHACHA:
                streamCipher = new ChaChaEngine();
                break;
            case CipherAlgorithm.CHACHA20_POLY1305:
                aeadCipher = new ChaCha20Poly1305();
                break;
            case CipherAlgorithm.CHACHA7539:
                streamCipher = new ChaCha7539Engine();
                break;
            case CipherAlgorithm.DES:
                blockCipher = new DesEngine();
                break;
            case CipherAlgorithm.DESEDE:
                blockCipher = new DesEdeEngine();
                break;
            case CipherAlgorithm.ELGAMAL:
                asymBlockCipher = new ElGamalEngine();
                break;
            case CipherAlgorithm.GOST28147:
                blockCipher = new Gost28147Engine();
                break;
            case CipherAlgorithm.HC128:
                streamCipher = new HC128Engine();
                break;
            case CipherAlgorithm.HC256:
                streamCipher = new HC256Engine();
                break;
            case CipherAlgorithm.IDEA:
                blockCipher = new IdeaEngine();
                break;
            case CipherAlgorithm.NOEKEON:
                blockCipher = new NoekeonEngine();
                break;
            case CipherAlgorithm.PBEWITHSHAAND128BITRC4:
            case CipherAlgorithm.PBEWITHSHAAND40BITRC4:
                streamCipher = new RC4Engine();
                break;
            case CipherAlgorithm.RC2:
                blockCipher = new RC2Engine();
                break;
            case CipherAlgorithm.RC5:
                blockCipher = new RC532Engine();
                break;
            case CipherAlgorithm.RC5_64:
                blockCipher = new RC564Engine();
                break;
            case CipherAlgorithm.RC6:
                blockCipher = new RC6Engine();
                break;
            case CipherAlgorithm.RIJNDAEL:
                blockCipher = new RijndaelEngine();
                break;
            case CipherAlgorithm.RSA:
                asymBlockCipher = new RsaBlindedEngine();
                break;
            case CipherAlgorithm.SALSA20:
                streamCipher = new Salsa20Engine();
                break;
            case CipherAlgorithm.SEED:
                blockCipher = new SeedEngine();
                break;
            case CipherAlgorithm.SERPENT:
                blockCipher = new SerpentEngine();
                break;
            case CipherAlgorithm.SKIPJACK:
                blockCipher = new SkipjackEngine();
                break;
            case CipherAlgorithm.SM4:
                blockCipher = new SM4Engine();
                break;
            case CipherAlgorithm.TEA:
                blockCipher = new TeaEngine();
                break;
            case CipherAlgorithm.THREEFISH_256:
                blockCipher = new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256);
                break;
            case CipherAlgorithm.THREEFISH_512:
                blockCipher = new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512);
                break;
            case CipherAlgorithm.THREEFISH_1024:
                blockCipher = new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024);
                break;
            case CipherAlgorithm.TNEPRES:
                blockCipher = new TnepresEngine();
                break;
            case CipherAlgorithm.TWOFISH:
                blockCipher = new TwofishEngine();
                break;
            case CipherAlgorithm.VMPC:
                streamCipher = new VmpcEngine();
                break;
            case CipherAlgorithm.VMPC_KSA3:
                streamCipher = new VmpcKsa3Engine();
                break;
            case CipherAlgorithm.XTEA:
                blockCipher = new XteaEngine();
            case CipherAlgorithm.LIBSECUREXTEA:
                blockCipher = new LibSecureXteaEngine();
                break;
            default:
                return null;
            }

            if (aeadCipher != null)
            {
                if (parts.Length > 1)
                    throw new ArgumentException("Modes and paddings cannot be applied to AEAD ciphers");

                return new BufferedAeadCipher(aeadCipher);
            }

            if (streamCipher != null)
            {
                if (parts.Length > 1)
                    throw new ArgumentException("Modes and paddings not used for stream ciphers");

                return new BufferedStreamCipher(streamCipher);
            }


            bool cts = false;
            bool padded = true;
            IBlockCipherPadding padding = null;
            IAeadBlockCipher aeadBlockCipher = null;

            if (parts.Length > 2)
            {
                if (streamCipher != null)
                    throw new ArgumentException("Paddings not used for stream ciphers");

                string paddingName = parts[2];

                CipherPadding cipherPadding;
                if (paddingName == "")
                {
                    cipherPadding = CipherPadding.RAW;
                }
                else if (paddingName == "X9.23PADDING")
                {
                    cipherPadding = CipherPadding.X923PADDING;
                }
                else
                {
                    try
                    {
                        cipherPadding = Enums.GetEnumValue<CipherPadding>(paddingName);
                    }
                    catch (ArgumentException)
                    {
                        return null;
                    }
                }

                switch (cipherPadding)
                {
                case CipherPadding.NOPADDING:
                    padded = false;
                    break;
                case CipherPadding.RAW:
                    break;
                case CipherPadding.ISO10126PADDING:
                case CipherPadding.ISO10126D2PADDING:
                case CipherPadding.ISO10126_2PADDING:
                    padding = new ISO10126d2Padding();
                    break;
                case CipherPadding.ISO7816_4PADDING:
                case CipherPadding.ISO9797_1PADDING:
                    padding = new ISO7816d4Padding();
                    break;
                case CipherPadding.ISO9796_1:
                case CipherPadding.ISO9796_1PADDING:
                    asymBlockCipher = new ISO9796d1Encoding(asymBlockCipher);
                    break;
                case CipherPadding.OAEP:
                case CipherPadding.OAEPPADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher);
                    break;
                case CipherPadding.OAEPWITHMD5ANDMGF1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new MD5Digest());
                    break;
                case CipherPadding.OAEPWITHSHA1ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA_1ANDMGF1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha1Digest());
                    break;
                case CipherPadding.OAEPWITHSHA224ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA_224ANDMGF1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha224Digest());
                    break;
                case CipherPadding.OAEPWITHSHA256ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA_256ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA256ANDMGF1WITHSHA256PADDING:
                case CipherPadding.OAEPWITHSHA_256ANDMGF1WITHSHA_256PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha256Digest());
                    break;
                case CipherPadding.OAEPWITHSHA256ANDMGF1WITHSHA1PADDING:
                case CipherPadding.OAEPWITHSHA_256ANDMGF1WITHSHA_1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha256Digest(), new Sha1Digest(), null);
                    break;
                case CipherPadding.OAEPWITHSHA384ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA_384ANDMGF1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha384Digest());
                    break;
                case CipherPadding.OAEPWITHSHA512ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA_512ANDMGF1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha512Digest());
                    break;
                case CipherPadding.PKCS1:
                case CipherPadding.PKCS1PADDING:
                    asymBlockCipher = new Pkcs1Encoding(asymBlockCipher);
                    break;
                case CipherPadding.PKCS5:
                case CipherPadding.PKCS5PADDING:
                case CipherPadding.PKCS7:
                case CipherPadding.PKCS7PADDING:
                    padding = new Pkcs7Padding();
                    break;
                case CipherPadding.TBCPADDING:
                    padding = new TbcPadding();
                    break;
                case CipherPadding.WITHCTS:
                    cts = true;
                    break;
                case CipherPadding.X923PADDING:
                    padding = new X923Padding();
                    break;
                case CipherPadding.ZEROBYTEPADDING:
                    padding = new ZeroBytePadding();
                    break;
                default:
                    return null;
                }
            }

            string mode = "";
            IBlockCipherMode blockCipherMode = null;
            if (parts.Length > 1)
            {
                mode = parts[1];

                int di = GetDigitIndex(mode);
                string modeName = di >= 0 ? mode.Substring(0, di) : mode;

                try
                {
                    CipherMode cipherMode = modeName == ""
                        ? CipherMode.NONE
                        : Enums.GetEnumValue<CipherMode>(modeName);

                    switch (cipherMode)
                    {
                    case CipherMode.ECB:
                    case CipherMode.NONE:
                        break;
                    case CipherMode.CBC:
                        blockCipherMode = new CbcBlockCipher(blockCipher);
                        break;
                    case CipherMode.CCM:
                        aeadBlockCipher = new CcmBlockCipher(blockCipher);
                        break;
                    case CipherMode.CFB:
                    {
                        int bits = (di < 0)
                            ?	8 * blockCipher.GetBlockSize()
                            :	int.Parse(mode.Substring(di));
    
                        blockCipherMode = new CfbBlockCipher(blockCipher, bits);
                        break;
                    }
                    case CipherMode.CTR:
                        blockCipherMode = new SicBlockCipher(blockCipher);
                        break;
                    case CipherMode.CTS:
                        cts = true;
                        blockCipherMode = new CbcBlockCipher(blockCipher);
                        break;
                    case CipherMode.EAX:
                        aeadBlockCipher = new EaxBlockCipher(blockCipher);
                        break;
                    case CipherMode.GCM:
                        aeadBlockCipher = new GcmBlockCipher(blockCipher);
                        break;
                    case CipherMode.GOFB:
                        blockCipherMode = new GOfbBlockCipher(blockCipher);
                        break;
                    case CipherMode.OCB:
                        aeadBlockCipher = new OcbBlockCipher(blockCipher, CreateBlockCipher(cipherAlgorithm));
                        break;
                    case CipherMode.OFB:
                    {
                        int bits = (di < 0)
                            ?	8 * blockCipher.GetBlockSize()
                            :	int.Parse(mode.Substring(di));
    
                        blockCipherMode = new OfbBlockCipher(blockCipher, bits);
                        break;
                    }
                    case CipherMode.OPENPGPCFB:
                        blockCipherMode = new OpenPgpCfbBlockCipher(blockCipher);
                        break;
                    case CipherMode.SIC:
                        if (blockCipher.GetBlockSize() < 16)
                        {
                            throw new ArgumentException("Warning: SIC-Mode can become a twotime-pad if the blocksize of the cipher is too small. Use a cipher with a block size of at least 128 bits (e.g. AES)");
                        }
                        blockCipherMode = new SicBlockCipher(blockCipher);
                        break;
                    default:
                        return null;
                    }
                }
                catch (ArgumentException)
                {
                    return null;
                }
            }

            if (aeadBlockCipher != null)
            {
                if (cts)
                    throw new SecurityUtilityException("CTS mode not valid for AEAD ciphers.");
                if (padded && parts.Length > 2 && parts[2] != "")
                    throw new SecurityUtilityException("Bad padding specified for AEAD cipher.");

                return new BufferedAeadBlockCipher(aeadBlockCipher);
            }

            if (blockCipher != null)
            {
                if (blockCipherMode == null)
                {
                    blockCipherMode = EcbBlockCipher.GetBlockCipherMode(blockCipher);
                }

                if (cts)
                {
                    return new CtsBlockCipher(blockCipherMode);
                }

                if (padding != null)
                {
                    return new PaddedBufferedBlockCipher(blockCipherMode, padding);
                }

                if (!padded || blockCipherMode.IsPartialBlockOkay)
                {
                    return new BufferedBlockCipher(blockCipherMode);
                }

                return new PaddedBufferedBlockCipher(blockCipherMode);
            }

            if (asymBlockCipher != null)
            {
                return new BufferedAsymmetricBlockCipher(asymBlockCipher);
            }

            return null;
        }

        private static int GetDigitIndex(string s)
        {
            for (int i = 0; i < s.Length; ++i)
            {
                if (char.IsDigit(s[i]))
                    return i;
            }

            return -1;
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

        private static IBlockCipher CreateBlockCipher(CipherAlgorithm cipherAlgorithm)
        {
            switch (cipherAlgorithm)
            {
            case CipherAlgorithm.AES: return AesUtilities.CreateEngine();
            case CipherAlgorithm.ARIA: return new AriaEngine();
            case CipherAlgorithm.BLOWFISH: return new BlowfishEngine();
            case CipherAlgorithm.CAMELLIA: return new CamelliaEngine();
            case CipherAlgorithm.CAST5: return new Cast5Engine();
            case CipherAlgorithm.CAST6: return new Cast6Engine();
            case CipherAlgorithm.DES: return new DesEngine();
            case CipherAlgorithm.DESEDE: return new DesEdeEngine();
            case CipherAlgorithm.GOST28147: return new Gost28147Engine();
            case CipherAlgorithm.IDEA: return new IdeaEngine();
            case CipherAlgorithm.NOEKEON: return new NoekeonEngine();
            case CipherAlgorithm.RC2: return new RC2Engine();
            case CipherAlgorithm.RC5: return new RC532Engine();
            case CipherAlgorithm.RC5_64: return new RC564Engine();
            case CipherAlgorithm.RC6: return new RC6Engine();
            case CipherAlgorithm.RIJNDAEL: return new RijndaelEngine();
            case CipherAlgorithm.SEED: return new SeedEngine();
            case CipherAlgorithm.SERPENT: return new SerpentEngine();
            case CipherAlgorithm.SKIPJACK: return new SkipjackEngine();
            case CipherAlgorithm.SM4: return new SM4Engine();
            case CipherAlgorithm.TEA: return new TeaEngine();
            case CipherAlgorithm.THREEFISH_256: return new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256);
            case CipherAlgorithm.THREEFISH_512: return new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512);
            case CipherAlgorithm.THREEFISH_1024: return new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024);
            case CipherAlgorithm.TNEPRES: return new TnepresEngine();
            case CipherAlgorithm.TWOFISH: return new TwofishEngine();
            case CipherAlgorithm.XTEA: return new XteaEngine();
            case CipherAlgorithm.LIBSECUREXTEA: return new LibSecureXteaEngine();
            default:
                throw new SecurityUtilityException("Cipher " + cipherAlgorithm + " not recognised or not a block cipher");
            }
        }
    }
}
