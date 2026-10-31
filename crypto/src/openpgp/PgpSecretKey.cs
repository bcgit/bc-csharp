using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>General class to handle a PGP secret key object.</summary>
    public class PgpSecretKey
        : PgpObject
    {
        private readonly SecretKeyPacket secret;
        private readonly PgpPublicKey pub;

        internal PgpSecretKey(SecretKeyPacket secret, PgpPublicKey pub)
        {
            this.secret = secret;
            this.pub = pub;
        }

        internal PgpSecretKey(PgpPrivateKey privKey, PgpPublicKey pubKey, SymmetricKeyAlgorithmTag encAlgorithm,
            byte[] rawPassPhrase, bool clearPassPhrase, bool useSha1, SecureRandom rand, bool isMasterKey)
        {
            this.pub = pubKey;

            bool isV6 = pubKey.Version == PublicKeyPacket.Version6;
            byte[] material = EncodeSecretKeyMaterial(privKey, pubKey);
            byte[] keyData = null;

            try
            {
                if (isV6 && encAlgorithm != SymmetricKeyAlgorithmTag.Null && PgpAead.IsSupportedCipher(encAlgorithm))
                {
                    // RFC 9580 3.7.2 and 13.7: version 6 keys are protected with AEAD, and Argon2 is recommended
                    PgpSecretKeyProtection protection = PgpSecretKeyProtection.AeadArgon2(encAlgorithm,
                        AeadAlgorithmTag.Ocb, S2k.Argon2Params.MemoryConstrainedParameters(rand), rawPassPhrase);
                    try
                    {
                        this.secret = ProtectKeyData(pub.publicPk, isMasterKey, material, protection, rand);
                    }
                    finally
                    {
                        protection.Clear();
                        if (clearPassPhrase && rawPassPhrase != null)
                        {
                            Arrays.ZeroMemory(rawPassPhrase);
                        }
                    }
                    return;
                }

                // RFC 9580 9.3: IDEA, TripleDES and CAST5 are only for decryption
                // TODO[api] Refuse them for version 3 and 4 keys too
                if (isV6 && PgpUtilities.IsDecryptOnlyCipher(encAlgorithm))
                    throw new PgpException("symmetric algorithm not allowed for version 6 keys: " + encAlgorithm);

                // Unprotected keys (S2K usage 0) of version 4 carry the 2-octet checksum (RFC 9580 5.5.3); those of
                // version 6 have none. Protected keys of version 4 and 6 use the SHA-1 hash (usage 254): RFC 9580
                // 3.7.2.1 does not allow to generate the checksum form (usage 255), so useSha1 only matters for
                // version 3 keys.
                bool sha1Check = (useSha1 || pub.Version >= 4) && encAlgorithm != SymmetricKeyAlgorithmTag.Null;
                keyData = isV6 && encAlgorithm == SymmetricKeyAlgorithmTag.Null
                    ? Arrays.Clone(material)
                    : Arrays.Concatenate(material, Checksum(sha1Check, material, material.Length));

                if (encAlgorithm == SymmetricKeyAlgorithmTag.Null)
                {
                    if (isMasterKey)
                    {
                        this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, null, null, keyData);
                    }
                    else
                    {
                        this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, null, null, keyData);
                    }

                    // the packet holds the key data now
                    keyData = null;
                }
                else
                {
                    S2k s2k;
                    byte[] iv;

                    byte[] encData;
                    if (pub.Version >= 4)
                    {
                        // RFC 9580 9.5: no S2K with MD5, SHA-1 or RIPEMD-160 in new packets
                        encData = EncryptKeyDataV4(keyData, encAlgorithm, HashAlgorithmTag.Sha256, rawPassPhrase,
                            clearPassPhrase, rand, out s2k, out iv);
                    }
                    else
                    {
                        encData = EncryptKeyDataV3(keyData, encAlgorithm, rawPassPhrase, clearPassPhrase, rand, out s2k,
                            out iv);
                    }

                    int s2kUsage = sha1Check ? SecretKeyPacket.UsageSha1 : SecretKeyPacket.UsageChecksum;

                    if (isMasterKey)
                    {
                        this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                    else
                    {
                        this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                }
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception encrypting key", e);
            }
            finally
            {
                Arrays.ZeroMemory(material);
                if (keyData != null)
                {
                    Arrays.ZeroMemory(keyData);
                }
            }
        }

        /// <summary>Protect the key with a <see cref="PgpSecretKeyProtection"/>.</summary>
        internal PgpSecretKey(PgpPrivateKey privKey, PgpPublicKey pubKey, PgpSecretKeyProtection protection,
            SecureRandom rand, bool isMasterKey)
        {
            this.pub = pubKey;

            byte[] material = EncodeSecretKeyMaterial(privKey, pubKey);
            try
            {
                this.secret = ProtectKeyData(pubKey.publicPk, isMasterKey, material, protection, rand);
            }
            finally
            {
                Arrays.ZeroMemory(material);
            }
        }

        private static SecretKeyPacket CreateSecretKeyPacket(PublicKeyPacket pubPk, bool isMasterKey,
            SymmetricKeyAlgorithmTag encAlgorithm, AeadAlgorithmTag aeadAlgorithm, int s2kUsage, S2k s2k, byte[] iv,
            byte[] keyData)
        {
            return isMasterKey
                ? new SecretKeyPacket(pubPk, encAlgorithm, aeadAlgorithm, s2kUsage, s2k, iv, keyData)
                : new SecretSubkeyPacket(pubPk, encAlgorithm, aeadAlgorithm, s2kUsage, s2k, iv, keyData);
        }

        /// <summary>Build the secret key packet for the (cleartext) key material.</summary>
        private static SecretKeyPacket ProtectKeyData(PublicKeyPacket pubPk, bool isMasterKey, byte[] material,
            PgpSecretKeyProtection protection, SecureRandom random)
        {
            if (protection == null)
                throw new ArgumentNullException(nameof(protection));
            if (pubPk.Version < PublicKeyPacket.Version4)
                throw new PgpException("protection of secret keys requires a version 4 or version 6 key");

            bool isV6 = pubPk.Version == PublicKeyPacket.Version6;
            byte[] rawPassPhrase = protection.GetPassPhrase();
            try
            {
                switch (protection.Usage)
                {
                case SecretKeyPacket.UsageNone:
                {
                    byte[] keyData = isV6
                        ? Arrays.Clone(material)
                        : Arrays.Concatenate(material, Checksum(useSha1: false, material, material.Length));

                    return CreateSecretKeyPacket(pubPk, isMasterKey, SymmetricKeyAlgorithmTag.Null, 0,
                        SecretKeyPacket.UsageNone, null, null, keyData);
                }
                case SecretKeyPacket.UsageSha1:
                {
                    // the factories of the protection refuse weak S2K hashes (RFC 9580 9.5)
                    S2k s2k = S2k.GenerateSaltedAndIterated(random, protection.S2kDigest, protection.S2kCount);
                    KeyParameter key = PgpUtilities.DoMakeKeyFromPassPhrase(protection.Cipher, s2k, rawPassPhrase,
                        clearPassPhrase: false);

                    byte[] data = Arrays.Concatenate(material, Checksum(useSha1: true, material, material.Length));
                    try
                    {
                        byte[] iv = null;
                        byte[] encData = EncryptData(protection.Cipher, key, data, 0, data.Length, random, ref iv);

                        return CreateSecretKeyPacket(pubPk, isMasterKey, protection.Cipher, 0,
                            SecretKeyPacket.UsageSha1, s2k, iv, encData);
                    }
                    finally
                    {
                        Arrays.ZeroMemory(data);
                    }
                }
                case SecretKeyPacket.UsageAead:
                {
                    // RFC 9580 5.5.3: also for version 4 keys, with the packet version in the info and the associated
                    // data
                    S2k s2k;
                    if (protection.Argon2Template != null)
                    {
                        var template = protection.Argon2Template;
                        s2k = S2k.Argon2S2k(new S2k.Argon2Params(template.Passes, template.Parallelism,
                            template.MemorySizeExponent, random));
                    }
                    else
                    {
                        s2k = S2k.GenerateSaltedAndIterated(random, protection.S2kDigest, protection.S2kCount);
                    }

                    byte[] s2kKey = PgpUtilities.DoMakeKeyFromPassPhrase(protection.Cipher, s2k, rawPassPhrase,
                        clearPassPhrase: false).GetKey();
                    byte[] kek = null;
                    try
                    {
                        byte[] info = AeadKeyInfo(isMasterKey, pubPk, protection.Cipher, protection.Aead);
                        kek = PgpAead.Hkdf(s2kKey, null, info,
                            SymmetricKeyUtilities.GetKeyLengthInOctets(protection.Cipher));

                        byte[] nonce = SecureRandom.GetNextBytes(random, AeadUtilities.GetIVLength(protection.Aead));
                        byte[] encData = PgpAead.EncryptOneShot(protection.Cipher, protection.Aead, kek, nonce,
                            AeadAssociatedData(isMasterKey, pubPk), material);

                        return CreateSecretKeyPacket(pubPk, isMasterKey, protection.Cipher, protection.Aead,
                            SecretKeyPacket.UsageAead, s2k, nonce, encData);
                    }
                    finally
                    {
                        Arrays.ZeroMemory(s2kKey);
                        if (kek != null)
                        {
                            Arrays.ZeroMemory(kek);
                        }
                    }
                }
                default:
                    throw new PgpException("unknown secret key protection");
                }
            }
            finally
            {
                if (rawPassPhrase != null)
                {
                    Arrays.ZeroMemory(rawPassPhrase);
                }
            }
        }

        /// <summary>The packet tag (with the new-format bit) of the secret key packet, as used in AEAD inputs.</summary>
        private static byte AeadPacketTag(bool isMasterKey) =>
            (byte)((isMasterKey ? (int)PacketTag.SecretKey : (int)PacketTag.SecretSubkey) | 0xC0);

        /// <summary>HKDF info for the key encryption key of an AEAD protected secret key (RFC 9580 5.5.3).</summary>
        private static byte[] AeadKeyInfo(bool isMasterKey, PublicKeyPacket pubPk, SymmetricKeyAlgorithmTag cipher,
            AeadAlgorithmTag aead)
        {
            return new byte[]{ AeadPacketTag(isMasterKey), pubPk.VersionByte, (byte)cipher, (byte)aead };
        }

        /// <summary>The associated data for an AEAD protected secret key: the tag and the public key material.</summary>
        private static byte[] AeadAssociatedData(bool isMasterKey, PublicKeyPacket pubPk) =>
            Arrays.Prepend(pubPk.GetEncodedContents(), AeadPacketTag(isMasterKey));

        private static void CheckV6S2k(S2k s2k)
        {
            // RFC 9580 9.5: no key derivation with MD5, SHA-1 or RIPEMD-160 for version 6 keys
            if (s2k != null && s2k.Type != S2k.Argon2 && PgpUtilities.IsWeakS2kHash(s2k.HashAlgorithm))
                throw new PgpException("S2K hash algorithm not allowed for version 6 keys: " + s2k.HashAlgorithm);
        }

        private static BcpgObject CreateSecretBcpgKey(PgpPrivateKey privKey, PgpPublicKey pubKey)
        {
            BcpgObject secKey;

            switch (pubKey.Algorithm)
            {
            case PublicKeyAlgorithmTag.RsaEncrypt:
            case PublicKeyAlgorithmTag.RsaSign:
            case PublicKeyAlgorithmTag.RsaGeneral:
                RsaPrivateCrtKeyParameters rsK = (RsaPrivateCrtKeyParameters) privKey.Key;
                secKey = new RsaSecretBcpgKey(rsK.Exponent, rsK.P, rsK.Q);
                break;
            case PublicKeyAlgorithmTag.Dsa:
                DsaPrivateKeyParameters dsK = (DsaPrivateKeyParameters) privKey.Key;
                secKey = new DsaSecretBcpgKey(dsK.X);
                break;
            case PublicKeyAlgorithmTag.ECDH:
            {
                if (privKey.Key is ECPrivateKeyParameters ecdhK)
                {
                    secKey = new ECSecretBcpgKey(ecdhK.D);
                }
                else
                {
                    // The native format for X25519 private keys is little-endian
                    X25519PrivateKeyParameters xK = (X25519PrivateKeyParameters)privKey.Key;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    secKey = new ECSecretBcpgKey(new BigInteger(1, xK.DataSpan, bigEndian: false));
#else
                    secKey = new ECSecretBcpgKey(new BigInteger(1, xK.GetEncoded(), bigEndian: false));
#endif
                }
                break;
            }
            case PublicKeyAlgorithmTag.ECDsa:
                ECPrivateKeyParameters ecK = (ECPrivateKeyParameters)privKey.Key;
                secKey = new ECSecretBcpgKey(ecK.D);
                break;
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
            {
                if (privKey.Key is Ed25519PrivateKeyParameters ed25519K)
                {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    secKey = new EdSecretBcpgKey(new BigInteger(1, ed25519K.DataSpan));
#else
                    secKey = new EdSecretBcpgKey(new BigInteger(1, ed25519K.GetEncoded()));
#endif
                }
                else if (privKey.Key is Ed448PrivateKeyParameters ed448K)
                {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    secKey = new EdSecretBcpgKey(new BigInteger(1, ed448K.DataSpan));
#else
                    secKey = new EdSecretBcpgKey(new BigInteger(1, ed448K.GetEncoded()));
#endif
                }
                else
                {
                    throw new PgpException("unknown EdDSA key class");
                }
                break;
            }
            case PublicKeyAlgorithmTag.ElGamalEncrypt:
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                ElGamalPrivateKeyParameters esK = (ElGamalPrivateKeyParameters) privKey.Key;
                secKey = new ElGamalSecretBcpgKey(esK.X);
                break;
            case PublicKeyAlgorithmTag.X25519:
            {
                if (!(privKey.Key is X25519PrivateKeyParameters x25519K))
                    throw new PgpException("unknown key class");

                byte[] encoding = x25519K.GetEncoded();
                secKey = new X25519SecretBcpgKey(encoding);
                Arrays.ZeroMemory(encoding);
                break;
            }
            case PublicKeyAlgorithmTag.X448:
            {
                if (!(privKey.Key is X448PrivateKeyParameters x448K))
                    throw new PgpException("unknown key class");

                byte[] encoding = x448K.GetEncoded();
                secKey = new X448SecretBcpgKey(encoding);
                Arrays.ZeroMemory(encoding);
                break;
            }
            case PublicKeyAlgorithmTag.Ed25519:
            {
                if (!(privKey.Key is Ed25519PrivateKeyParameters ed25519K))
                    throw new PgpException("unknown key class");

                byte[] encoding = ed25519K.GetEncoded();
                secKey = new Ed25519SecretBcpgKey(encoding);
                Arrays.ZeroMemory(encoding);
                break;
            }
            case PublicKeyAlgorithmTag.Ed448:
            {
                if (!(privKey.Key is Ed448PrivateKeyParameters ed448K))
                    throw new PgpException("unknown key class");

                byte[] encoding = ed448K.GetEncoded();
                secKey = new Ed448SecretBcpgKey(encoding);
                Arrays.ZeroMemory(encoding);
                break;
            }
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
            {
                if (!(privKey.Key is SlhDsaPrivateKeyParameters slhDsaK) ||
                    slhDsaK.Parameters != PgpUtilities.GetSlhDsaParameters(pubKey.Algorithm))
                {
                    throw new PgpException("unknown key class");
                }

                byte[] encoding = slhDsaK.GetEncoded();
                secKey = new SlhDsaSecretBcpgKey(pubKey.Algorithm, encoding);
                Arrays.ZeroMemory(encoding);
                break;
            }
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
            {
                if (!(privKey.Key is MLDsa65Ed25519PrivateKeyParameters mlDsaK))
                    throw new PgpException("unknown key class");

                byte[] seed = mlDsaK.MLDsaKey.GetSeed();
                byte[] ed = mlDsaK.Ed25519Key.GetEncoded();
                byte[] material = Arrays.Concatenate(ed, seed);
                secKey = new MLDsa65Ed25519SecretBcpgKey(material);
                Arrays.ZeroMemory(seed);
                Arrays.ZeroMemory(ed);
                Arrays.ZeroMemory(material);
                break;
            }
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
            {
                if (!(privKey.Key is MLDsa87Ed448PrivateKeyParameters mlDsaK))
                    throw new PgpException("unknown key class");

                byte[] seed = mlDsaK.MLDsaKey.GetSeed();
                byte[] ed = mlDsaK.Ed448Key.GetEncoded();
                byte[] material = Arrays.Concatenate(ed, seed);
                secKey = new MLDsa87Ed448SecretBcpgKey(material);
                Arrays.ZeroMemory(seed);
                Arrays.ZeroMemory(ed);
                Arrays.ZeroMemory(material);
                break;
            }
            case PublicKeyAlgorithmTag.MLKem1024_X448:
            {
                if (!(privKey.Key is MLKem1024X448PrivateKeyParameters mlKemX448K))
                    throw new PgpException("unknown key class");

                byte[] seed = mlKemX448K.MLKemKey.GetSeed() ?? throw new PgpException("ML-KEM key has no seed");
                byte[] x448 = mlKemX448K.X448Key.GetEncoded();
                byte[] material = Arrays.Concatenate(x448, seed);
                secKey = new MLKem1024X448SecretBcpgKey(material);
                Arrays.ZeroMemory(seed);
                Arrays.ZeroMemory(x448);
                Arrays.ZeroMemory(material);
                break;
            }
            case PublicKeyAlgorithmTag.MLKem768_X25519:
            {
                if (!(privKey.Key is MLKem768X25519PrivateKeyParameters mlKemX25519K))
                    throw new PgpException("unknown key class");

                byte[] seed = mlKemX25519K.MLKemKey.GetSeed() ?? throw new PgpException("ML-KEM key has no seed");
                byte[] x25519 = mlKemX25519K.X25519Key.GetEncoded();
                byte[] material = Arrays.Concatenate(x25519, seed);
                secKey = new MLKem768X25519SecretBcpgKey(material);
                Arrays.ZeroMemory(seed);
                Arrays.ZeroMemory(x25519);
                Arrays.ZeroMemory(material);
                break;
            }
            default:
                throw new PgpException("unknown key class");
            }

            return secKey;
        }

        private static byte[] EncodeSecretBcpgKey(BcpgObject secKey)
        {
            MemoryStream bOut = new MemoryStream();
            BcpgOutputStream pOut = new BcpgOutputStream(bOut);

            secKey.Encode(pOut);

            byte[] encoding = bOut.ToArray();
            Arrays.ZeroMemory(bOut.GetBuffer());
            return encoding;
        }

        /// <summary>The encoding of the secret key material, without copies of it left behind.</summary>
        private static byte[] EncodeSecretKeyMaterial(PgpPrivateKey privKey, PgpPublicKey pubKey)
        {
            BcpgObject secKey = CreateSecretBcpgKey(privKey, pubKey);
            try
            {
                return EncodeSecretBcpgKey(secKey);
            }
            finally
            {
                (secKey as OctetArrayBcpgKey)?.Clear();
            }
        }

        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public PgpSecretKey(int certificationLevel, PgpKeyPair keyPair, string id,
            SymmetricKeyAlgorithmTag encAlgorithm, char[] passPhrase, bool useSha1,
            PgpSignatureSubpacketVector hashedPackets, PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(certificationLevel, keyPair, id, encAlgorithm, false, passPhrase, useSha1, hashedPackets, unhashedPackets, rand)
        {
        }

        /// <remarks>
        /// If utf8PassPhrase is true, conversion of the passphrase to bytes uses UTF8, otherwise the conversion
        /// is performed using Convert.ToByte(), which is the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public PgpSecretKey(int certificationLevel, PgpKeyPair keyPair, string id,
            SymmetricKeyAlgorithmTag encAlgorithm, bool utf8PassPhrase, char[] passPhrase, bool useSha1,
            PgpSignatureSubpacketVector hashedPackets, PgpSignatureSubpacketVector unhashedPackets, SecureRandom rand)
            : this(certificationLevel, keyPair, id, encAlgorithm,
                PgpUtilities.EncodePassPhrase(passPhrase, utf8PassPhrase), true, useSha1, hashedPackets,
                unhashedPackets, rand)
        {
        }

        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public PgpSecretKey(int certificationLevel, PgpKeyPair keyPair, string id,
            SymmetricKeyAlgorithmTag encAlgorithm, byte[] rawPassPhrase, bool useSha1,
            PgpSignatureSubpacketVector hashedPackets, PgpSignatureSubpacketVector unhashedPackets, SecureRandom rand)
            : this(certificationLevel, keyPair, id, encAlgorithm, rawPassPhrase, false, useSha1, hashedPackets,
                unhashedPackets, rand)
        {
        }

        internal PgpSecretKey(int certificationLevel, PgpKeyPair keyPair, string id,
            SymmetricKeyAlgorithmTag encAlgorithm, byte[] rawPassPhrase, bool clearPassPhrase, bool useSha1,
            PgpSignatureSubpacketVector hashedPackets, PgpSignatureSubpacketVector unhashedPackets, SecureRandom rand)
            : this(keyPair.PrivateKey,
                CertifiedPublicKey(certificationLevel, keyPair, id, hashedPackets, unhashedPackets), encAlgorithm,
                rawPassPhrase, clearPassPhrase, useSha1, rand, true)
        {
        }

        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public PgpSecretKey(int certificationLevel, PgpKeyPair keyPair, string id,
            SymmetricKeyAlgorithmTag encAlgorithm, HashAlgorithmTag hashAlgorithm, char[] passPhrase,
            bool useSha1, PgpSignatureSubpacketVector hashedPackets, PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(certificationLevel, keyPair, id, encAlgorithm, hashAlgorithm, false, passPhrase, useSha1,
                hashedPackets, unhashedPackets, rand)
        {
        }

        /// <remarks>
        /// If utf8PassPhrase is true, conversion of the passphrase to bytes uses UTF8, otherwise
        /// the conversion is performed using Convert.ToByte(), which is the historical behaviour of the library (1.7
        /// and earlier).
        /// </remarks>
        public PgpSecretKey(int certificationLevel, PgpKeyPair keyPair, string id,
            SymmetricKeyAlgorithmTag encAlgorithm, HashAlgorithmTag hashAlgorithm, bool utf8PassPhrase,
            char[] passPhrase, bool useSha1, PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets, SecureRandom rand)
            : this(certificationLevel, keyPair, id, encAlgorithm, hashAlgorithm,
                PgpUtilities.EncodePassPhrase(passPhrase, utf8PassPhrase), true, useSha1, hashedPackets,
                unhashedPackets, rand)
        {
        }

        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public PgpSecretKey(int certificationLevel, PgpKeyPair keyPair, string id,
            SymmetricKeyAlgorithmTag encAlgorithm, HashAlgorithmTag hashAlgorithm, byte[] rawPassPhrase,
            bool useSha1, PgpSignatureSubpacketVector hashedPackets, PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(certificationLevel, keyPair, id, encAlgorithm, hashAlgorithm, rawPassPhrase, false, useSha1,
                hashedPackets, unhashedPackets, rand)
        {
        }

        internal PgpSecretKey(int certificationLevel, PgpKeyPair keyPair, string id,
            SymmetricKeyAlgorithmTag encAlgorithm, HashAlgorithmTag hashAlgorithm, byte[] rawPassPhrase,
            bool clearPassPhrase, bool useSha1, PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets, SecureRandom rand)
            : this(keyPair.PrivateKey,
                CertifiedPublicKey(certificationLevel, keyPair, id, hashedPackets, unhashedPackets, hashAlgorithm),
                encAlgorithm, rawPassPhrase, clearPassPhrase, useSha1, rand, true)
        {
        }

        // RFC 9580 9.5: no signatures with MD5, SHA-1 or RIPEMD-160, and 5.2.3.2-5: a hash as large as the key needs
        private static PgpPublicKey CertifiedPublicKey(int certificationLevel, PgpKeyPair keyPair, string id,
            PgpSignatureSubpacketVector hashedPackets, PgpSignatureSubpacketVector unhashedPackets) =>
            CertifiedPublicKey(certificationLevel, keyPair, id, hashedPackets, unhashedPackets,
                PgpUtilities.GetDefaultHashAlgorithm(keyPair.PublicKey));

        private static PgpPublicKey CertifiedPublicKey(int certificationLevel, PgpKeyPair keyPair, string id,
            PgpSignatureSubpacketVector hashedPackets, PgpSignatureSubpacketVector unhashedPackets,
            HashAlgorithmTag hashAlgorithm)
        {
            PgpSignatureGenerator sGen;
            try
            {
                sGen = new PgpSignatureGenerator(keyPair.PublicKey.Algorithm, hashAlgorithm);
            }
            catch (Exception e)
            {
                throw new PgpException("Creating signature generator: " + e.Message, e);
            }

            //
            // Generate the certification
            //
            sGen.InitSign(certificationLevel, keyPair.PrivateKey);

            sGen.SetHashedSubpackets(hashedPackets);
            sGen.SetUnhashedSubpackets(unhashedPackets);

            try
            {
                PgpSignature certification = sGen.GenerateCertification(id, keyPair.PublicKey);
                PgpPublicKey certified = PgpPublicKey.AddCertification(keyPair.PublicKey, id, certification);

                // RFC 9580 5.2.3.10, 10.1.1: a version 6 key is not used without a direct-key signature
                if (keyPair.PublicKey.Version == PublicKeyPacket.Version6)
                {
                    sGen.InitSign(PgpSignature.DirectKey, keyPair.PrivateKey);
                    sGen.SetHashedSubpackets(hashedPackets);
                    sGen.SetUnhashedSubpackets(unhashedPackets);
                    certified = PgpPublicKey.AddCertification(certified,
                        sGen.GenerateCertification(keyPair.PublicKey));
                }
                return certified;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception doing certification: " + e.Message, e);
            }
        }

        public PgpSecretKey(int certificationLevel, PublicKeyAlgorithmTag algorithm, AsymmetricKeyParameter pubKey,
            AsymmetricKeyParameter privKey, DateTime time, string id, SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase, PgpSignatureSubpacketVector hashedPackets, PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(certificationLevel, new PgpKeyPair(algorithm, pubKey, privKey, time), id, encAlgorithm, passPhrase,
                false, hashedPackets, unhashedPackets, rand)
        {
        }

        public PgpSecretKey(int certificationLevel, PublicKeyAlgorithmTag algorithm, AsymmetricKeyParameter pubKey,
            AsymmetricKeyParameter privKey, DateTime time, string id, SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase, bool useSha1, PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets, SecureRandom rand)
            : this(certificationLevel, new PgpKeyPair(algorithm, pubKey, privKey, time), id, encAlgorithm, passPhrase,
                useSha1, hashedPackets, unhashedPackets, rand)
        {
        }

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for signing.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for use with signing.
        /// </returns>
        public bool IsSigningKey
        {
            get
            {
                switch (pub.Algorithm)
                {
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                case PublicKeyAlgorithmTag.Dsa:
                case PublicKeyAlgorithmTag.ECDsa:
                case PublicKeyAlgorithmTag.EdDsa_Legacy:
                case PublicKeyAlgorithmTag.Ed25519:
                case PublicKeyAlgorithmTag.Ed448:
                case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
                case PublicKeyAlgorithmTag.MLDsa87_Ed448:
                case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
                case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
                case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    return true;
                default:
                    return false;
                }
            }
        }

        /// <summary>True, if this is a master key.</summary>
        public bool IsMasterKey => pub.IsMasterKey;

        /// <summary>Detect if the Secret Key's Private Key is empty or not</summary>
        public bool IsPrivateKeyEmpty
        {
            get
            {
                byte[] secKeyData = secret.GetSecretKeyData();

                return secKeyData == null || secKeyData.Length < 1;
            }
        }

        /// <summary>The algorithm the key is encrypted with.</summary>
        public SymmetricKeyAlgorithmTag KeyEncryptionAlgorithm => secret.EncAlgorithm;

        /// <summary>The Key ID of the public key associated with this key.</summary>
        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => pub.KeyId;

        /// <summary>The fingerprint of the public key associated with this key.</summary>
        public byte[] GetFingerprint() => pub.GetFingerprint();

        /// <summary>Return the S2K usage associated with this key.</summary>
        public int S2kUsage => secret.S2kUsage;

        /// <summary>Return the S2K used to process this key.</summary>
        public S2k S2k => secret.S2k;

        /// <summary>The public key associated with this key.</summary>
        public PgpPublicKey PublicKey => pub;

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable<string> UserIds => pub.GetUserIds();

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable<PgpUserAttributeSubpacketVector> UserAttributes => pub.GetUserAttributes();

        /// <summary>
        /// The length of the data that follows the key material in the cleartext key data: the 2-octet checksum, the
        /// SHA-1 hash, or nothing.
        /// </summary>
        private int GetKeyDataTrailerLength()
        {
            switch (secret.S2kUsage)
            {
            case SecretKeyPacket.UsageNone:
                return secret.PublicKeyPacket.Version == PublicKeyPacket.Version6 ? 0 : 2;
            case SecretKeyPacket.UsageSha1:
                return 20;
            case SecretKeyPacket.UsageAead:
                return 0;
            default:
                return 2;
            }
        }

        /// <summary>The key material without checksum or hash.</summary>
        private byte[] ExtractKeyMaterial(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            byte[] data = ExtractKeyData(rawPassPhrase, clearPassPhrase);
            try
            {
                return Arrays.CopyOfRange(data, 0, data.Length - GetKeyDataTrailerLength());
            }
            finally
            {
                WipeKeyData(data);
            }
        }

        /// <summary>Wipe decrypted key data, unless it is the data of the packet (of an unprotected key).</summary>
        private void WipeKeyData(byte[] data)
        {
            if (!ReferenceEquals(data, secret.GetSecretKeyData()))
            {
                Arrays.ZeroMemory(data);
            }
        }

        private byte[] ExtractKeyData(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            byte[] encData = secret.GetSecretKeyData();

            if (secret.PublicKeyPacket.Version == PublicKeyPacket.Version6)
            {
                // RFC 9580 5.5.3: version 6 keys do not use the checksum or the cipher-ID forms of the usage octet
                if (secret.S2kUsage == SecretKeyPacket.UsageNone)
                    return encData;

                if (secret.S2kUsage != SecretKeyPacket.UsageSha1 && secret.S2kUsage != SecretKeyPacket.UsageAead)
                    throw new PgpException("unsupported S2K usage for a version 6 key");

                CheckV6S2k(secret.S2k);
            }

            SymmetricKeyAlgorithmTag encAlgorithm = secret.EncAlgorithm;
            if (encAlgorithm == SymmetricKeyAlgorithmTag.Null)
                return encData;

            if (secret.S2kUsage == SecretKeyPacket.UsageAead)
                return ExtractAeadKeyData(encData, rawPassPhrase, clearPassPhrase);

            // TODO Factor this block out as 'decryptData'
            try
            {
                KeyParameter key = PgpUtilities.DoMakeKeyFromPassPhrase(encAlgorithm, secret.S2k, rawPassPhrase,
                    clearPassPhrase);
                byte[] iv = secret.GetIV();
                byte[] data;

                if (secret.PublicKeyPacket.Version >= 4)
                {
                    data = RecoverKeyData(encAlgorithm, "/CFB/NoPadding", key, iv, encData, 0, encData.Length);

                    bool useSha1 = secret.S2kUsage == SecretKeyPacket.UsageSha1;
                    byte[] check = Checksum(useSha1, data, useSha1 ? data.Length - 20 : data.Length - 2);

                    if (!Arrays.FixedTimeEquals(check.Length, check, 0, data, data.Length - check.Length))
                        throw new PgpException("Checksum mismatch in checksum of " + check.Length + " bytes");
                }
                else // version 2 or 3, RSA only.
                {
                    data = new byte[encData.Length];

                    iv = Arrays.Clone(iv);

                    //
                    // read in the four numbers
                    //
                    int pos = 0;

                    for (int i = 0; i != 4; i++)
                    {
                        int encLen = ((((encData[pos] & 0xff) << 8) | (encData[pos + 1] & 0xff)) + 7) / 8;

                        data[pos] = encData[pos];
                        data[pos + 1] = encData[pos + 1];
                        pos += 2;

                        if (encLen > (encData.Length - pos))
                            throw new PgpException("out of range encLen found in encData");

                        byte[] tmp = RecoverKeyData(encAlgorithm, "/CFB/NoPadding", key, iv, encData, pos, encLen);
                        Array.Copy(tmp, 0, data, pos, encLen);
                        pos += encLen;

                        if (i != 3)
                        {
                            Array.Copy(encData, pos - iv.Length, iv, 0, iv.Length);
                        }
                    }

                    //
                    // verify and copy checksum
                    //

                    data[pos] = encData[pos];
                    data[pos + 1] = encData[pos + 1];

                    int cs = ((encData[pos] << 8) & 0xff00) | (encData[pos + 1] & 0xff);
                    int calcCs = 0;
                    for (int j = 0; j < pos; j++)
                    {
                        calcCs += data[j] & 0xff;
                    }

                    calcCs &= 0xffff;
                    if (calcCs != cs)
                    {
                        throw new PgpException("Checksum mismatch: passphrase wrong, expected "
                            + cs.ToString("X")
                            + " found " + calcCs.ToString("X"));
                    }
                }

                return data;
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception decrypting key", e);
            }
        }

        /// <summary>RFC 9580 5.5.3: decrypt the key material of a key with S2K usage octet 253.</summary>
        private byte[] ExtractAeadKeyData(byte[] encData, byte[] rawPassPhrase, bool clearPassPhrase)
        {
            SymmetricKeyAlgorithmTag encAlgorithm = secret.EncAlgorithm;
            AeadAlgorithmTag aeadAlgorithm = secret.AeadAlgorithm;
            PublicKeyPacket pubPk = secret.PublicKeyPacket;
            bool isMasterKey = !(secret is SecretSubkeyPacket);

            if (!PgpAead.IsSupportedCipher(encAlgorithm))
                throw new PgpException("unsupported symmetric algorithm for AEAD protected key: " + encAlgorithm);

            byte[] s2kKey = null, kek = null;
            try
            {
                s2kKey = PgpUtilities.DoMakeKeyFromPassPhrase(encAlgorithm, secret.S2k, rawPassPhrase,
                    clearPassPhrase).GetKey();
                kek = PgpAead.Hkdf(s2kKey, null, AeadKeyInfo(isMasterKey, pubPk, encAlgorithm, aeadAlgorithm),
                    SymmetricKeyUtilities.GetKeyLengthInOctets(encAlgorithm));

                return PgpAead.DecryptOneShot(encAlgorithm, aeadAlgorithm, kek, secret.GetIV(),
                    AeadAssociatedData(isMasterKey, pubPk), encData);
            }
            catch (InvalidCipherTextException e)
            {
                throw new PgpException("Exception decrypting key", e);
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception decrypting key", e);
            }
            finally
            {
                if (s2kKey != null)
                {
                    Arrays.ZeroMemory(s2kKey);
                }
                if (kek != null)
                {
                    Arrays.ZeroMemory(kek);
                }
            }
        }

        private static byte[] RecoverKeyData(SymmetricKeyAlgorithmTag encAlgorithm, string modeAndPadding,
            KeyParameter key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
        {
            IBufferedCipher c;
            try
            {
                string cName = PgpUtilities.GetSymmetricCipherName(encAlgorithm);
                c = CipherUtilities.GetCipher(cName + modeAndPadding);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }

            c.Init(forEncryption: false, new ParametersWithIV(key, iv));

            return c.DoFinal(keyData, keyOff, keyLen);
        }

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public PgpPrivateKey ExtractPrivateKey(char[] passPhrase) =>
            DoExtractPrivateKey(PgpUtilities.EncodePassPhrase(passPhrase, utf8: false), clearPassPhrase: true);

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8.
        /// </remarks>
        public PgpPrivateKey ExtractPrivateKeyUtf8(char[] passPhrase) =>
            DoExtractPrivateKey(PgpUtilities.EncodePassPhrase(passPhrase, utf8: true), clearPassPhrase: true);

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public PgpPrivateKey ExtractPrivateKeyRaw(byte[] rawPassPhrase) =>
            DoExtractPrivateKey(rawPassPhrase, clearPassPhrase: false);

        internal PgpPrivateKey DoExtractPrivateKey(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            if (IsPrivateKeyEmpty)
                return null;

            PublicKeyPacket pubPk = secret.PublicKeyPacket;

            if (secret.IsMalformed)
                throw new PgpException("malformed secret key packet");

            byte[] data = null;
            OctetArrayBcpgKey secretKeyMaterial = null;
            try
            {
                data = ExtractKeyData(rawPassPhrase, clearPassPhrase);
                var dataIn = new MemoryStream(data, false);
                BcpgInputStream bcpgIn = BcpgInputStream.Wrap(dataIn);
                AsymmetricKeyParameter privateKey;

                // RFC 9580 3.2: the MPIs of version 6 keys are minimal, the secret ones too
                bool strictMpis = pubPk.Version == PublicKeyPacket.Version6;
                switch (pubPk.Algorithm)
                {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    RsaPublicBcpgKey rsaPub = (RsaPublicBcpgKey)pubPk.Key;
                    RsaSecretBcpgKey rsaPriv = new RsaSecretBcpgKey(bcpgIn, strictMpis);
                    RsaPrivateCrtKeyParameters rsaPrivSpec = new RsaPrivateCrtKeyParameters(
                        rsaPriv.Modulus,
                        rsaPub.PublicExponent,
                        rsaPriv.PrivateExponent,
                        rsaPriv.PrimeP,
                        rsaPriv.PrimeQ,
                        rsaPriv.PrimeExponentP,
                        rsaPriv.PrimeExponentQ,
                        rsaPriv.CrtCoefficient);
                    privateKey = rsaPrivSpec;
                    break;
                case PublicKeyAlgorithmTag.Dsa:
                    DsaPublicBcpgKey dsaPub = (DsaPublicBcpgKey)pubPk.Key;
                    DsaSecretBcpgKey dsaPriv = new DsaSecretBcpgKey(bcpgIn);
                    DsaParameters dsaParams = new DsaParameters(dsaPub.P, dsaPub.Q, dsaPub.G);
                    privateKey = new DsaPrivateKeyParameters(dsaPriv.X, dsaParams);
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                {
                    ECDHPublicBcpgKey ecdhPub = (ECDHPublicBcpgKey)pubPk.Key;
                    ECSecretBcpgKey ecdhPriv = new ECSecretBcpgKey(bcpgIn, strictMpis);
                    var curveOid = ecdhPub.CurveOid;

                    if (EdECObjectIdentifiers.id_X25519.Equals(curveOid) ||
                        CryptlibObjectIdentifiers.curvey25519.Equals(curveOid))
                    {
                        // 'reverse' because the native format for X25519 private keys is little-endian
                        privateKey = PrivateKeyFactory.CreateKey(new PrivateKeyInfo(
                            new AlgorithmIdentifier(curveOid),
                            new DerOctetString(Arrays.ReverseInPlace(BigIntegers.AsUnsignedByteArray(ecdhPriv.X)))));
                    }
                    else if (EdECObjectIdentifiers.id_X448.Equals(curveOid))
                    {
                        // 'reverse' because the native format for X448 private keys is little-endian
                        privateKey = PrivateKeyFactory.CreateKey(new PrivateKeyInfo(
                            new AlgorithmIdentifier(curveOid),
                            new DerOctetString(Arrays.ReverseInPlace(BigIntegers.AsUnsignedByteArray(ecdhPriv.X)))));
                    }
                    else
                    {
                        privateKey = new ECPrivateKeyParameters("ECDH", ecdhPriv.X, ecdhPub.CurveOid);
                    }
                    break;
                }
                case PublicKeyAlgorithmTag.ECDsa:
                {
                    ECPublicBcpgKey ecdsaPub = (ECPublicBcpgKey)pubPk.Key;
                    ECSecretBcpgKey ecdsaPriv = new ECSecretBcpgKey(bcpgIn, strictMpis);

                    privateKey = new ECPrivateKeyParameters("ECDSA", ecdsaPriv.X, ecdsaPub.CurveOid);
                    break;
                }
                case PublicKeyAlgorithmTag.EdDsa_Legacy:
                {
                    EdDsaPublicBcpgKey eddsaPub = (EdDsaPublicBcpgKey)pubPk.Key;
                    EdSecretBcpgKey ecdsaPriv = new EdSecretBcpgKey(bcpgIn);

                    var curveOid = eddsaPub.CurveOid;
                    if (EdECObjectIdentifiers.id_Ed25519.Equals(curveOid) ||
                        GnuObjectIdentifiers.Ed25519.Equals(curveOid))
                    {
                        privateKey = PrivateKeyFactory.CreateKey(new PrivateKeyInfo(
                            new AlgorithmIdentifier(curveOid),
                            new DerOctetString(BigIntegers.AsUnsignedByteArray(Ed25519.SecretKeySize, ecdsaPriv.X))));
                    }
                    else if (EdECObjectIdentifiers.id_Ed448.Equals(curveOid))
                    {
                        privateKey = PrivateKeyFactory.CreateKey(new PrivateKeyInfo(
                            new AlgorithmIdentifier(curveOid),
                            new DerOctetString(BigIntegers.AsUnsignedByteArray(Ed448.SecretKeySize, ecdsaPriv.X))));
                    }
                    else 
                    {
                        throw new InvalidOperationException();
                    }
                    break;
                }
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    ElGamalPublicBcpgKey elPub = (ElGamalPublicBcpgKey)pubPk.Key;
                    ElGamalSecretBcpgKey elPriv = new ElGamalSecretBcpgKey(bcpgIn);
                    ElGamalParameters elParams = new ElGamalParameters(elPub.P, elPub.G);
                    privateKey = new ElGamalPrivateKeyParameters(elPriv.X, elParams);
                    break;
                case PublicKeyAlgorithmTag.X25519:
                {
                    secretKeyMaterial = new X25519SecretBcpgKey(bcpgIn);
                    byte[] encoding = secretKeyMaterial.GetKey();
                    try
                    {
                        var x25519K = new X25519PrivateKeyParameters(encoding);

                        if (!Arrays.FixedTimeEquals(x25519K.GeneratePublicKey().GetEncoded(),
                            ((X25519PublicBcpgKey)pubPk.Key).GetKey()))
                        {
                            throw new PgpException("X25519 secret key does not match its public key");
                        }

                        privateKey = x25519K;
                    }
                    finally
                    {
                        Arrays.ZeroMemory(encoding);
                    }
                    break;
                }
                case PublicKeyAlgorithmTag.X448:
                {
                    secretKeyMaterial = new X448SecretBcpgKey(bcpgIn);
                    byte[] encoding = secretKeyMaterial.GetKey();
                    try
                    {
                        var x448K = new X448PrivateKeyParameters(encoding);

                        if (!Arrays.FixedTimeEquals(x448K.GeneratePublicKey().GetEncoded(),
                            ((X448PublicBcpgKey)pubPk.Key).GetKey()))
                        {
                            throw new PgpException("X448 secret key does not match its public key");
                        }

                        privateKey = x448K;
                    }
                    finally
                    {
                        Arrays.ZeroMemory(encoding);
                    }
                    break;
                }
                case PublicKeyAlgorithmTag.Ed25519:
                {
                    secretKeyMaterial = new Ed25519SecretBcpgKey(bcpgIn);
                    byte[] encoding = secretKeyMaterial.GetKey();
                    try
                    {
                        var ed25519K = new Ed25519PrivateKeyParameters(encoding);

                        // the checksum of an unprotected key is not verified: check the key against its public key
                        if (!Arrays.FixedTimeEquals(ed25519K.GeneratePublicKey().GetEncoded(),
                            ((Ed25519PublicBcpgKey)pubPk.Key).GetKey()))
                        {
                            throw new PgpException("Ed25519 secret key does not match its public key");
                        }

                        privateKey = ed25519K;
                    }
                    finally
                    {
                        Arrays.ZeroMemory(encoding);
                    }
                    break;
                }
                case PublicKeyAlgorithmTag.Ed448:
                {
                    secretKeyMaterial = new Ed448SecretBcpgKey(bcpgIn);
                    byte[] encoding = secretKeyMaterial.GetKey();
                    try
                    {
                        var ed448K = new Ed448PrivateKeyParameters(encoding);

                        if (!Arrays.FixedTimeEquals(ed448K.GeneratePublicKey().GetEncoded(),
                            ((Ed448PublicBcpgKey)pubPk.Key).GetKey()))
                        {
                            throw new PgpException("Ed448 secret key does not match its public key");
                        }

                        privateKey = ed448K;
                    }
                    finally
                    {
                        Arrays.ZeroMemory(encoding);
                    }
                    break;
                }
                case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
                case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
                case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                {
                    var slhDsaSecret = new SlhDsaSecretBcpgKey(pubPk.Algorithm, bcpgIn);
                    secretKeyMaterial = slhDsaSecret;
                    privateKey = DecodeSlhDsa(pubPk, slhDsaSecret);
                    break;
                }
                case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
                {
                    var mlDsaSecret = new MLDsa65Ed25519SecretBcpgKey(bcpgIn);
                    secretKeyMaterial = mlDsaSecret;
                    privateKey = DecodeMLDsa65Ed25519((MLDsa65Ed25519PublicBcpgKey)pubPk.Key, mlDsaSecret);
                    break;
                }
                case PublicKeyAlgorithmTag.MLDsa87_Ed448:
                {
                    var mlDsaSecret = new MLDsa87Ed448SecretBcpgKey(bcpgIn);
                    secretKeyMaterial = mlDsaSecret;
                    privateKey = DecodeMLDsa87Ed448((MLDsa87Ed448PublicBcpgKey)pubPk.Key, mlDsaSecret);
                    break;
                }
                case PublicKeyAlgorithmTag.MLKem768_X25519:
                {
                    var mlKemSecret = new MLKem768X25519SecretBcpgKey(bcpgIn);
                    secretKeyMaterial = mlKemSecret;
                    privateKey = DecodeMLKem768X25519((MLKem768X25519PublicBcpgKey)pubPk.Key, mlKemSecret);
                    break;
                }
                case PublicKeyAlgorithmTag.MLKem1024_X448:
                {
                    var mlKemSecret = new MLKem1024X448SecretBcpgKey(bcpgIn);
                    secretKeyMaterial = mlKemSecret;
                    privateKey = DecodeMLKem1024X448((MLKem1024X448PublicBcpgKey)pubPk.Key, mlKemSecret);
                    break;
                }
                default:
                    throw new PgpException("unknown public key algorithm encountered");
                }

                // RFC 9580 5.5.3: the key material must account for the whole cleartext of encrypted key material,
                // of version 6 keys, and of the algorithms introduced since version 4. Older unencrypted key material
                // is decoded leniently.
                bool exact = secret.S2kUsage != SecretKeyPacket.UsageNone || IsExactLengthRequired(pubPk);
                if (exact && dataIn.Length - dataIn.Position != GetKeyDataTrailerLength())
                    throw new PgpException("malformed secret key material");

                return new PgpPrivateKey(KeyId, pubPk, privateKey);
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception constructing key", e);
            }
            finally
            {
                secretKeyMaterial?.Clear();
                if (data != null)
                {
                    WipeKeyData(data);
                }
            }
        }

        private static bool IsExactLengthRequired(PublicKeyPacket pubPk)
        {
            if (pubPk.Version == PublicKeyPacket.Version6)
                return true;

            switch (pubPk.Algorithm)
            {
            case PublicKeyAlgorithmTag.X25519:
            case PublicKeyAlgorithmTag.X448:
            case PublicKeyAlgorithmTag.Ed25519:
            case PublicKeyAlgorithmTag.Ed448:
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
            case PublicKeyAlgorithmTag.MLKem768_X25519:
            case PublicKeyAlgorithmTag.MLKem1024_X448:
                return true;
            default:
                return false;
            }
        }

        private static SlhDsaPrivateKeyParameters DecodeSlhDsa(PublicKeyPacket pubPk, SlhDsaSecretBcpgKey secretKey)
        {
            byte[] encoding = secretKey.GetKey();
            try
            {
                var privateKey = SlhDsaPrivateKeyParameters.FromEncoding(
                    PgpUtilities.GetSlhDsaParameters(pubPk.Algorithm), encoding);

                // the secret key embeds the public key (PK.seed || PK.root): it has to be the one of the packet
                byte[] publicEncoding = ((SlhDsaPublicBcpgKey)pubPk.Key).GetKey();
                if (!Arrays.FixedTimeEquals(privateKey.GetPublicKeyEncoded(), publicEncoding))
                    throw new PgpException("SLH-DSA secret key does not match its public key");

                return privateKey;
            }
            finally
            {
                Arrays.ZeroMemory(encoding);
            }
        }

        private static MLDsa65Ed25519PrivateKeyParameters DecodeMLDsa65Ed25519(
            MLDsa65Ed25519PublicBcpgKey publicKey, MLDsa65Ed25519SecretBcpgKey secretKey)
        {
            byte[] ed25519 = secretKey.GetEd25519SecretKey();
            byte[] seed = secretKey.GetMLDsaSeed();
            try
            {
                var ed25519Key = new Ed25519PrivateKeyParameters(ed25519);
                var mlDsaKey = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, seed);

                // check the expanded key against its public key packet before using it
                if (!Arrays.FixedTimeEquals(ed25519Key.GeneratePublicKey().GetEncoded(),
                        publicKey.GetEd25519PublicKey())
                    || !Arrays.FixedTimeEquals(mlDsaKey.GetPublicKeyEncoded(), publicKey.GetMLDsaPublicKey()))
                {
                    throw new PgpException("ML-DSA-65+Ed25519 secret key does not match its public key");
                }

                return new MLDsa65Ed25519PrivateKeyParameters(ed25519Key, mlDsaKey);
            }
            finally
            {
                Arrays.ZeroMemory(ed25519);
                Arrays.ZeroMemory(seed);
            }
        }

        private static MLDsa87Ed448PrivateKeyParameters DecodeMLDsa87Ed448(
            MLDsa87Ed448PublicBcpgKey publicKey, MLDsa87Ed448SecretBcpgKey secretKey)
        {
            byte[] ed448 = secretKey.GetEd448SecretKey();
            byte[] seed = secretKey.GetMLDsaSeed();
            try
            {
                var ed448Key = new Ed448PrivateKeyParameters(ed448);
                var mlDsaKey = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_87, seed);

                if (!Arrays.FixedTimeEquals(ed448Key.GeneratePublicKey().GetEncoded(), publicKey.GetEd448PublicKey())
                    || !Arrays.FixedTimeEquals(mlDsaKey.GetPublicKeyEncoded(), publicKey.GetMLDsaPublicKey()))
                {
                    throw new PgpException("ML-DSA-87+Ed448 secret key does not match its public key");
                }

                return new MLDsa87Ed448PrivateKeyParameters(ed448Key, mlDsaKey);
            }
            finally
            {
                Arrays.ZeroMemory(ed448);
                Arrays.ZeroMemory(seed);
            }
        }

        private static MLKem1024X448PrivateKeyParameters DecodeMLKem1024X448(
            MLKem1024X448PublicBcpgKey publicKey, MLKem1024X448SecretBcpgKey secretKey)
        {
            byte[] x448 = secretKey.GetX448SecretKey();
            byte[] seed = secretKey.GetMLKemSeed();
            try
            {
                var x448Key = new X448PrivateKeyParameters(x448);
                var mlKemKey = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_1024, seed);

                // check the expanded key against its public key packet before using it
                if (!Arrays.FixedTimeEquals(x448Key.GeneratePublicKey().GetEncoded(), publicKey.GetX448PublicKey())
                    || !Arrays.FixedTimeEquals(mlKemKey.GetPublicKeyEncoded(), publicKey.GetMLKemPublicKey()))
                {
                    throw new PgpException("ML-KEM-1024+X448 secret key does not match its public key");
                }

                return new MLKem1024X448PrivateKeyParameters(x448Key, mlKemKey);
            }
            finally
            {
                Arrays.ZeroMemory(x448);
                Arrays.ZeroMemory(seed);
            }
        }

        private static MLKem768X25519PrivateKeyParameters DecodeMLKem768X25519(
            MLKem768X25519PublicBcpgKey publicKey, MLKem768X25519SecretBcpgKey secretKey)
        {
            byte[] x25519 = secretKey.GetX25519SecretKey();
            byte[] seed = secretKey.GetMLKemSeed();
            try
            {
                var x25519Key = new X25519PrivateKeyParameters(x25519);
                var mlKemKey = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);

                // The checksum of an unprotected key is not verified, so check the expanded key against its public
                // key packet before using it.
                if (!Arrays.FixedTimeEquals(x25519Key.GeneratePublicKey().GetEncoded(), publicKey.GetX25519PublicKey())
                    || !Arrays.FixedTimeEquals(mlKemKey.GetPublicKeyEncoded(), publicKey.GetMLKemPublicKey()))
                {
                    throw new PgpException("ML-KEM-768+X25519 secret key does not match its public key");
                }

                return new MLKem768X25519PrivateKeyParameters(x25519Key, mlKemKey);
            }
            finally
            {
                Arrays.ZeroMemory(x25519);
                Arrays.ZeroMemory(seed);
            }
        }

        private static byte[] Checksum(bool useSha1, byte[] bytes, int length)
        {
            if (useSha1)
            {
                try
                {
                    var digest = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha1);

                    return DigestUtilities.DoFinal(digest, bytes, 0, length);
                }
                catch (Exception e)
                {
                    throw new PgpException("Can't find SHA-1", e);
                }
            }
            else
            {
                int checkSum = 0;
                for (int i = 0; i != length; i++)
                {
                    checkSum += bytes[i];
                }

                return Pack.UInt16_To_BE((ushort)checkSum);
            }
        }

        public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        public void Encode(Stream outStr)
        {
            BcpgOutputStream bcpgOut = BcpgOutputStream.Wrap(outStr);

            secret.Encode(bcpgOut);

            pub.trustPk?.Encode(bcpgOut);

            if (pub.subSigs == null) // is not a sub key
            {
                foreach (PgpSignature keySig in pub.keySigs)
                {
                    keySig.Encode(bcpgOut);
                }

                for (int i = 0; i != pub.ids.Count; i++)
                {
                    var pubID = pub.ids[i];
                    if (pubID is UserIdPacket id)
                    {
                        id.Encode(bcpgOut);
                    }
                    else if (pubID is PgpUserAttributeSubpacketVector v)
                    {
                        new UserAttributePacket(v.ToSubpacketArray()).Encode(bcpgOut);
                    }
                    else
                    {
                        throw new InvalidOperationException();
                    }

                    pub.idTrusts[i]?.Encode(bcpgOut);

                    foreach (PgpSignature sig in pub.idSigs[i])
                    {
                        sig.Encode(bcpgOut);
                    }
                }
            }
            else
            {
                foreach (PgpSignature subSig in pub.subSigs)
                {
                    subSig.Encode(bcpgOut);
                }
            }

            // For clarity; really only required if using partial body lengths
            bcpgOut.Finish();
        }

        /// <summary>
        /// Return a copy of the passed in secret key, encrypted using a new password
        /// and the passed in algorithm.
        /// </summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        /// <param name="key">The PgpSecretKey to be copied.</param>
        /// <param name="oldPassPhrase">The current password for the key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="rand">Source of randomness.</param>
        public static PgpSecretKey CopyWithNewPassword(PgpSecretKey key, char[] oldPassPhrase, char[] newPassPhrase,
            SymmetricKeyAlgorithmTag newEncAlgorithm, SecureRandom rand)
        {
            var rawOldPassPhrase = PgpUtilities.EncodePassPhrase(oldPassPhrase, utf8: false);
            var rawNewPassPhrase = PgpUtilities.EncodePassPhrase(newPassPhrase, utf8: false);

            return DoCopyWithNewPassword(key, rawOldPassPhrase, rawNewPassPhrase, clearPassPhrase: true,
                newEncAlgorithm, rand);
        }

        /// <summary>
        /// Return a copy of the passed in secret key, encrypted using a new password
        /// and the passed in algorithm.
        /// </summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8.
        /// </remarks>
        /// <param name="key">The PgpSecretKey to be copied.</param>
        /// <param name="oldPassPhrase">The current password for the key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="rand">Source of randomness.</param>
        public static PgpSecretKey CopyWithNewPasswordUtf8(PgpSecretKey key, char[] oldPassPhrase, char[] newPassPhrase,
            SymmetricKeyAlgorithmTag newEncAlgorithm, SecureRandom rand)
        {
            var rawOldPassPhrase = PgpUtilities.EncodePassPhrase(oldPassPhrase, utf8: true);
            var rawNewPassPhrase = PgpUtilities.EncodePassPhrase(newPassPhrase, utf8: true);

            return DoCopyWithNewPassword(key, rawOldPassPhrase, rawNewPassPhrase, clearPassPhrase: true,
                newEncAlgorithm, rand);
        }

        /// <summary>
        /// Return a copy of the passed in secret key, encrypted using a new password
        /// and the passed in algorithm.
        /// </summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        /// <param name="key">The PgpSecretKey to be copied.</param>
        /// <param name="rawOldPassPhrase">The current password for the key.</param>
        /// <param name="rawNewPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="rand">Source of randomness.</param>
        public static PgpSecretKey CopyWithNewPasswordRaw(PgpSecretKey key, byte[] rawOldPassPhrase,
            byte[] rawNewPassPhrase, SymmetricKeyAlgorithmTag newEncAlgorithm, SecureRandom rand)
        {
            return DoCopyWithNewPassword(key, rawOldPassPhrase, rawNewPassPhrase, clearPassPhrase: false,
                newEncAlgorithm, rand);
        }

        internal static PgpSecretKey DoCopyWithNewPassword(PgpSecretKey key, byte[] rawOldPassPhrase,
            byte[] rawNewPassPhrase, bool clearPassPhrase, SymmetricKeyAlgorithmTag newEncAlgorithm, SecureRandom rand)
        {
            if (key.IsPrivateKeyEmpty)
                throw new PgpException("no private key in this SecretKey - public key present only.");

            if (key.secret.PublicKeyPacket.Version == PublicKeyPacket.Version6)
            {
                // RFC 9580 3.7.2 and 13.7: version 6 keys are protected with AEAD and Argon2 where the cipher allows
                // it, otherwise with S2K usage 254, never with the checksum form (usage 255)
                PgpSecretKeyProtection protection;
                if (newEncAlgorithm == SymmetricKeyAlgorithmTag.Null)
                {
                    protection = PgpSecretKeyProtection.None;
                }
                else if (PgpAead.IsSupportedCipher(newEncAlgorithm))
                {
                    protection = PgpSecretKeyProtection.AeadArgon2(newEncAlgorithm, AeadAlgorithmTag.Ocb,
                        S2k.Argon2Params.MemoryConstrainedParameters(rand), rawNewPassPhrase);
                }
                else
                {
                    // refuses IDEA, TripleDES and CAST5 (RFC 9580 9.3)
                    protection = PgpSecretKeyProtection.Cfb(newEncAlgorithm, HashAlgorithmTag.Sha256, 0x60,
                        rawNewPassPhrase);
                }

                try
                {
                    return DoCopyWithNewProtection(key, rawOldPassPhrase, clearPassPhrase, protection, rand);
                }
                finally
                {
                    if (clearPassPhrase && rawNewPassPhrase != null)
                    {
                        Arrays.ZeroMemory(rawNewPassPhrase);
                    }
                    protection.Clear();
                }
            }

            byte[] rawKeyData = key.ExtractKeyData(rawOldPassPhrase, clearPassPhrase);
            byte[] keyData = null;
            try
            {
                return CopyKeyData(key, rawKeyData, rawNewPassPhrase, clearPassPhrase, newEncAlgorithm, rand,
                    out keyData);
            }
            finally
            {
                // the cleartext key data, unless it went into the new packet as it is
                if (!ReferenceEquals(rawKeyData, keyData))
                {
                    key.WipeKeyData(rawKeyData);
                }
            }
        }

        private static PgpSecretKey CopyKeyData(PgpSecretKey key, byte[] rawKeyData, byte[] rawNewPassPhrase,
            bool clearPassPhrase, SymmetricKeyAlgorithmTag newEncAlgorithm, SecureRandom rand, out byte[] keyData)
        {
            int s2kUsage = key.secret.S2kUsage;
            byte[] iv = null;
            S2k s2k = null;
            PublicKeyPacket pubKeyPacket = key.secret.PublicKeyPacket;

            // the key material without the SHA-1 hash or the checksum (AEAD protected data has neither)
            int materialLength = rawKeyData.Length - key.GetKeyDataTrailerLength();

            if (newEncAlgorithm == SymmetricKeyAlgorithmTag.Null)
            {
                s2kUsage = SecretKeyPacket.UsageNone;
                if (materialLength == rawKeyData.Length - 2)
                {
                    // the checksum is there already
                    keyData = rawKeyData;
                }
                else
                {
                    // RFC 9580 5.5.3: unprotected keys of version 3 and 4 carry the 2-octet checksum
                    keyData = Arrays.Concatenate(Arrays.CopyOfRange(rawKeyData, 0, materialLength),
                        Checksum(useSha1: false, rawKeyData, materialLength));
                }
            }
            else
            {
                try
                {
                    // TODO[api] Refuse IDEA, TripleDES and CAST5 (RFC 9580 9.3), as for version 6 keys
                    if (pubKeyPacket.Version >= 4)
                    {
                        // RFC 9580 3.7.2.1: of the CFB forms only usage 254, with the SHA-1 hash, may be generated
                        s2kUsage = SecretKeyPacket.UsageSha1;
                        byte[] data = Arrays.Concatenate(Arrays.CopyOfRange(rawKeyData, 0, materialLength),
                            Checksum(useSha1: true, rawKeyData, materialLength));
                        try
                        {
                            // RFC 9580 9.5: no S2K with MD5, SHA-1 or RIPEMD-160 in new packets
                            keyData = EncryptKeyDataV4(data, newEncAlgorithm, HashAlgorithmTag.Sha256,
                                rawNewPassPhrase, clearPassPhrase, rand, out s2k, out iv);
                        }
                        finally
                        {
                            Arrays.ZeroMemory(data);
                        }
                    }
                    else
                    {
                        if (s2kUsage == SecretKeyPacket.UsageNone)
                        {
                            s2kUsage = SecretKeyPacket.UsageChecksum;
                        }

                        keyData = EncryptKeyDataV3(rawKeyData, newEncAlgorithm, rawNewPassPhrase, clearPassPhrase,
                            rand, out s2k, out iv);
                    }
                }
                catch (PgpException)
                {
                    throw;
                }
                catch (Exception e)
                {
                    throw new PgpException("Exception encrypting key", e);
                }
            }

            SecretKeyPacket secret;
            if (key.secret is SecretSubkeyPacket)
            {
                secret = new SecretSubkeyPacket(pubKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);
            }
            else
            {
                secret = new SecretKeyPacket(pubKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);
            }

            return new PgpSecretKey(secret, key.pub);
        }

        /// <summary>
        /// Return a copy of the passed in secret key with a different protection, for example AEAD protection with
        /// Argon2 for a version 6 key.
        /// </summary>
        /// <remarks>
        /// The pass phrase held by <paramref name="protection"/> is wiped afterwards, so the protection cannot be used
        /// for another key. Only keys of version 4 and 6 are supported.
        /// </remarks>
        /// <param name="key">The PgpSecretKey to be copied.</param>
        /// <param name="rawOldPassPhrase">The current pass phrase of the key, if it is protected.</param>
        /// <param name="protection">The new protection.</param>
        /// <param name="random">Source of randomness.</param>
        public static PgpSecretKey CopyWithNewProtection(PgpSecretKey key, byte[] rawOldPassPhrase,
            PgpSecretKeyProtection protection, SecureRandom random)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.IsPrivateKeyEmpty)
                throw new PgpException("no private key in this SecretKey - public key present only.");

            protection?.CheckNotCleared();

            try
            {
                return DoCopyWithNewProtection(key, rawOldPassPhrase, clearPassPhrase: false, protection, random);
            }
            finally
            {
                protection?.Clear();
            }
        }

        private static PgpSecretKey DoCopyWithNewProtection(PgpSecretKey key, byte[] rawOldPassPhrase,
            bool clearPassPhrase, PgpSecretKeyProtection protection, SecureRandom random)
        {
            if (protection == null)
                throw new ArgumentNullException(nameof(protection));

            if (key.secret.PublicKeyPacket.Version < PublicKeyPacket.Version4)
                throw new PgpException("protection of secret keys requires a version 4 or version 6 key");

            byte[] material = key.ExtractKeyMaterial(rawOldPassPhrase, clearPassPhrase);
            try
            {
                PublicKeyPacket pubPk = key.secret.PublicKeyPacket;
                bool isMasterKey = !(key.secret is SecretSubkeyPacket);

                SecretKeyPacket secret = ProtectKeyData(pubPk, isMasterKey, material, protection, random);

                return new PgpSecretKey(secret, key.pub);
            }
            finally
            {
                Arrays.ZeroMemory(material);
            }
        }

        /// <summary>Replace the passed the public key on the passed in secret key.</summary>
        /// <param name="secretKey">Secret key to change.</param>
        /// <param name="publicKey">New public key.</param>
        /// <returns>A new secret key.</returns>
        /// <exception cref="ArgumentException">If KeyId's do not match.</exception>
        public static PgpSecretKey ReplacePublicKey(PgpSecretKey secretKey, PgpPublicKey publicKey)
        {
            if (publicKey.KeyId != secretKey.KeyId)
                throw new ArgumentException("KeyId's do not match");

            return new PgpSecretKey(secretKey.secret, publicKey);
        }

        private static byte[] EncryptKeyDataV3(byte[] rawKeyData, SymmetricKeyAlgorithmTag encAlgorithm,
            byte[] rawPassPhrase, bool clearPassPhrase, SecureRandom random, out S2k s2k, out byte[] iv)
        {
            // Version 2 or 3 - RSA Keys only

            s2k = null;
            iv = null;

            KeyParameter encKey = PgpUtilities.DoMakeKeyFromPassPhrase(encAlgorithm, s2k, rawPassPhrase,
                clearPassPhrase);

            byte[] keyData = new byte[rawKeyData.Length];

            //
            // process 4 numbers
            //
            int pos = 0;
            for (int i = 0; i != 4; i++)
            {
                int encLen = ((((rawKeyData[pos] & 0xff) << 8) | (rawKeyData[pos + 1] & 0xff)) + 7) / 8;

                keyData[pos] = rawKeyData[pos];
                keyData[pos + 1] = rawKeyData[pos + 1];

                if (encLen > (rawKeyData.Length - (pos + 2)))
                    throw new PgpException("out of range encLen found in rawKeyData");

                byte[] tmp;
                if (i == 0)
                {
                    tmp = EncryptData(encAlgorithm, encKey, rawKeyData, pos + 2, encLen, random, ref iv);
                }
                else
                {
                    byte[] tmpIv = Arrays.CopyOfRange(keyData, pos - iv.Length, pos);

                    tmp = EncryptData(encAlgorithm, encKey, rawKeyData, pos + 2, encLen, random, ref tmpIv);
                }

                Array.Copy(tmp, 0, keyData, pos + 2, tmp.Length);
                pos += 2 + encLen;
            }

            //
            // copy in checksum.
            //
            keyData[pos] = rawKeyData[pos];
            keyData[pos + 1] = rawKeyData[pos + 1];

            return keyData;
        }

        private static byte[] EncryptKeyDataV4(byte[] rawKeyData, SymmetricKeyAlgorithmTag encAlgorithm,
            HashAlgorithmTag hashAlgorithm, byte[] rawPassPhrase, bool clearPassPhrase, SecureRandom random,
            out S2k s2k, out byte[] iv)
        {
            // TODO Configurable iterations?
            s2k = S2k.GenerateSaltedAndIterated(random, hashAlgorithm, 0x60);

            KeyParameter key = PgpUtilities.DoMakeKeyFromPassPhrase(encAlgorithm, s2k, rawPassPhrase, clearPassPhrase);

            iv = null;
            return EncryptData(encAlgorithm, key, rawKeyData, 0, rawKeyData.Length, random, ref iv);
        }

        private static byte[] EncryptData(SymmetricKeyAlgorithmTag encAlgorithm, KeyParameter key, byte[] data,
            int dataOff, int dataLen, SecureRandom random, ref byte[] iv)
        {
            IBufferedCipher c;
            try
            {
                string cName = PgpUtilities.GetSymmetricCipherName(encAlgorithm);
                c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }

            if (iv == null)
            {
                iv = SecureRandom.GetNextBytes(random, c.GetBlockSize());
            }

            c.Init(true, new ParametersWithRandom(new ParametersWithIV(key, iv), random));

            return c.DoFinal(data, dataOff, dataLen);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
        /// </summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExpr(Stream inputStream, char[] passPhrase, PgpPublicKey pubKey)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            return DoParseSecretKeyFromSExpr(inputStream, rawPassPhrase, clearPassPhrase: true, pubKey);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
        /// </summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8.
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExprUtf8(Stream inputStream, char[] passPhrase,
            PgpPublicKey pubKey)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            return DoParseSecretKeyFromSExpr(inputStream, rawPassPhrase, clearPassPhrase: true, pubKey);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
        /// </summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExprRaw(Stream inputStream, byte[] rawPassPhrase,
            PgpPublicKey pubKey)
        {
            return DoParseSecretKeyFromSExpr(inputStream, rawPassPhrase, clearPassPhrase: false, pubKey);
        }

        internal static PgpSecretKey DoParseSecretKeyFromSExpr(Stream inputStream, byte[] rawPassPhrase,
            bool clearPassPhrase, PgpPublicKey pubKey)
        {
            SXprUtilities.SkipOpenParenthesis(inputStream);

            string type = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
            if (type.Equals("protected-private-key"))
            {
                SXprUtilities.SkipOpenParenthesis(inputStream);

                string curveName;

                string keyType = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                if (keyType.Equals("ecc"))
                {
                    SXprUtilities.SkipOpenParenthesis(inputStream);

                    string curveID = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                    curveName = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());

                    SXprUtilities.SkipCloseParenthesis(inputStream);
                }
                else
                {
                    throw new PgpException("no curve details found");
                }

                byte[] qVal;

                SXprUtilities.SkipOpenParenthesis(inputStream);

                type = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                if (type.Equals("q"))
                {
                    qVal = SXprUtilities.ReadBytes(inputStream, inputStream.ReadByte());
                }
                else
                {
                    throw new PgpException("no q value found");
                }

                SXprUtilities.SkipCloseParenthesis(inputStream);

                byte[] dValue = GetDValue(inputStream, rawPassPhrase, clearPassPhrase, curveName);
                // TODO: check SHA-1 hash.

                return CreateECSecretKey(pubKey, dValue);
            }

            throw new PgpException("unknown key type found");
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExpr(Stream inputStream, char[] passPhrase)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            return DoParseSecretKeyFromSExpr(inputStream, rawPassPhrase, clearPassPhrase: true);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8.
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExprUtf8(Stream inputStream, char[] passPhrase)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            return DoParseSecretKeyFromSExpr(inputStream, rawPassPhrase, clearPassPhrase: true);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExprRaw(Stream inputStream, byte[] rawPassPhrase) =>
            DoParseSecretKeyFromSExpr(inputStream, rawPassPhrase, clearPassPhrase: false);

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        internal static PgpSecretKey DoParseSecretKeyFromSExpr(Stream inputStream, byte[] rawPassPhrase,
            bool clearPassPhrase)
        {
            SXprUtilities.SkipOpenParenthesis(inputStream);

            string type = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
            if (type.Equals("protected-private-key"))
            {
                SXprUtilities.SkipOpenParenthesis(inputStream);

                string curveName;

                string keyType = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                if (keyType.Equals("ecc"))
                {
                    SXprUtilities.SkipOpenParenthesis(inputStream);

                    string curveID = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                    curveName = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());

                    if (Platform.StartsWith(curveName, "NIST "))
                    {
                        curveName = curveName.Substring("NIST ".Length);
                    }

                    SXprUtilities.SkipCloseParenthesis(inputStream);
                }
                else
                {
                    throw new PgpException("no curve details found");
                }

                byte[] qVal;

                SXprUtilities.SkipOpenParenthesis(inputStream);

                type = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                if (type.Equals("q"))
                {
                    qVal = SXprUtilities.ReadBytes(inputStream, inputStream.ReadByte());
                }
                else
                {
                    throw new PgpException("no q value found");
                }

                IBcpgKey key = new ECDsaPublicBcpgKey(ECNamedCurveTable.GetOid(curveName), new BigInteger(1, qVal));

                PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyPacket.Version4, PublicKeyAlgorithmTag.ECDsa,
                    DateTime.UtcNow, key);

                SXprUtilities.SkipCloseParenthesis(inputStream);

                byte[] dValue = GetDValue(inputStream, rawPassPhrase, clearPassPhrase, curveName);
                // TODO: check SHA-1 hash.

                return CreateECSecretKey(new PgpPublicKey(pubPacket), dValue);
            }

            throw new PgpException("unknown key type found");
        }

        private static PgpSecretKey CreateECSecretKey(PgpPublicKey pubKey, byte[] dValue)
        {
            byte[] secKeyData = new ECSecretBcpgKey(new BigInteger(1, dValue)).GetEncoded();
            var secretKeyPacket = new SecretKeyPacket(pubKey.PublicKeyPacket, SymmetricKeyAlgorithmTag.Null, s2k: null,
                iv: null, secKeyData);
            return new PgpSecretKey(secretKeyPacket, pubKey);
        }

        private static byte[] GetDValue(Stream inStr, byte[] rawPassPhrase, bool clearPassPhrase, string curveName)
        {
            string type;
            SXprUtilities.SkipOpenParenthesis(inStr);

            string protection;
            S2k s2k;
            byte[] iv;
            byte[] secKeyData;

            type = SXprUtilities.ReadString(inStr, inStr.ReadByte());
            if (type.Equals("protected"))
            {
                protection = SXprUtilities.ReadString(inStr, inStr.ReadByte());

                SXprUtilities.SkipOpenParenthesis(inStr);

                s2k = SXprUtilities.ParseS2k(inStr);

                iv = SXprUtilities.ReadBytes(inStr, inStr.ReadByte());

                SXprUtilities.SkipCloseParenthesis(inStr);

                secKeyData = SXprUtilities.ReadBytes(inStr, inStr.ReadByte());
            }
            else
            {
                throw new PgpException("protected block not found");
            }

            // TODO: recognise other algorithms
            KeyParameter key = PgpUtilities.DoMakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag.Aes128, s2k, rawPassPhrase,
                clearPassPhrase);

            byte[] data = RecoverKeyData(SymmetricKeyAlgorithmTag.Aes128, "/CBC/NoPadding", key, iv, secKeyData, 0,
                secKeyData.Length);

            //
            // parse the secret key S-expr
            //
            Stream keyIn = new MemoryStream(data, false);

            SXprUtilities.SkipOpenParenthesis(keyIn);
            SXprUtilities.SkipOpenParenthesis(keyIn);
            SXprUtilities.SkipOpenParenthesis(keyIn);
            //string name =
            SXprUtilities.ReadString(keyIn, keyIn.ReadByte());
            return SXprUtilities.ReadBytes(keyIn, keyIn.ReadByte());
        }
    }
}
