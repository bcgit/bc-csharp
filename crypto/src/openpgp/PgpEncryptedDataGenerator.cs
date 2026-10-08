using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Generator for encrypted objects.</summary>
    public class PgpEncryptedDataGenerator
        : IStreamGenerator
    {
        private BcpgOutputStream pOut;
        private CipherStream cOut;
        private IBufferedCipher c;
        private bool withIntegrityPacket;
        private bool oldFormat;
        private DigestStream digestOut;

        // v2 SEIPD mode (RFC 9580 5.13.2)
        private readonly bool m_isAead;
        private readonly AeadAlgorithmTag m_aeadAlgorithm;
        private readonly int m_chunkSizeOctet;
        private PgpAeadOutputStream m_aeadOut;

        private abstract class EncMethod
            : ContainedPacket
        {
            internal EncMethod()
#pragma warning disable CS0618 // Type or member is obsolete
                : base()
#pragma warning restore CS0618 // Type or member is obsolete
            {
            }

            protected byte[] sessionInfo;
            protected SymmetricKeyAlgorithmTag encAlgorithm;
            protected KeyParameter key;

            public abstract void AddSessionInfo(byte[] si, SecureRandom random);

            /// <summary>Protect the session key for a v2 SEIPD message (v6 ESK packets).</summary>
            public virtual void AddSessionKey(byte[] sessionKey, SymmetricKeyAlgorithmTag payloadAlgorithm,
                AeadAlgorithmTag aeadAlgorithm, SecureRandom random)
            {
                throw new PgpException("encryption method not supported for AEAD encrypted messages");
            }
        }

        /// <summary>Password based encryption for v2 SEIPD messages: a v6 SKESK packet (RFC 9580 5.3.2).</summary>
        private class AeadPbeMethod
            : EncMethod
        {
            private readonly S2k m_s2k;
            private readonly byte[] m_s2kKey;
            private SymmetricKeyEncSessionPacket m_packet;

            internal AeadPbeMethod(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k, byte[] s2kKey)
            {
                this.encAlgorithm = encAlgorithm;
                m_s2k = s2k;
                m_s2kKey = s2kKey;
            }

            public override void AddSessionInfo(byte[] si, SecureRandom random) =>
                throw new InvalidOperationException();

            public override void AddSessionKey(byte[] sessionKey, SymmetricKeyAlgorithmTag payloadAlgorithm,
                AeadAlgorithmTag aeadAlgorithm, SecureRandom random)
            {
                byte[] aad = SymmetricKeyEncSessionPacket.CreateAAData(SymmetricKeyEncSessionPacket.Version6,
                    encAlgorithm, aeadAlgorithm);
                byte[] kek = null;
                try
                {
                    kek = PgpAead.Hkdf(m_s2kKey, null, aad, SymmetricKeyUtilities.GetKeyLengthInOctets(encAlgorithm));

                    byte[] nonce = new byte[AeadUtilities.GetIVLength(aeadAlgorithm)];
                    random.NextBytes(nonce);

                    byte[] encrypted = PgpAead.EncryptOneShot(encAlgorithm, aeadAlgorithm, kek, nonce, aad,
                        sessionKey);
                    int keyLength = encrypted.Length - PgpAead.TagLength;

                    m_packet = SymmetricKeyEncSessionPacket.CreateV6Packet(encAlgorithm, aeadAlgorithm, nonce, m_s2k,
                        Arrays.CopyOfRange(encrypted, 0, keyLength),
                        Arrays.CopyOfRange(encrypted, keyLength, encrypted.Length));
                }
                finally
                {
                    if (kek != null)
                    {
                        Arrays.ZeroMemory(kek);
                    }
                }
            }

            public override void Encode(BcpgOutputStream pOut) => m_packet.Encode(pOut);
        }

        private class PbeMethod
            : EncMethod
        {
            private readonly S2k m_s2k;

            internal PbeMethod(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k, KeyParameter key)
            {
                this.encAlgorithm = encAlgorithm;
                m_s2k = s2k;
                this.key = key;
            }

            public KeyParameter GetKey() => key;

            public override void AddSessionInfo(byte[] si, SecureRandom random)
            {
                string cName = PgpUtilities.GetSymmetricCipherName(encAlgorithm);
                IBufferedCipher c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");

                byte[] iv = new byte[c.GetBlockSize()];
                c.Init(true, new ParametersWithRandom(new ParametersWithIV(key, iv), random));

                this.sessionInfo = c.DoFinal(si, 0, si.Length - 2);
            }

            public override void Encode(BcpgOutputStream pOut) =>
                SymmetricKeyEncSessionPacket.CreateV4Packet(encAlgorithm, m_s2k, sessionInfo).Encode(pOut);
        }

        private class PubMethod
            : EncMethod
        {
            internal PgpPublicKey pubKey;
            internal bool sessionKeyObfuscation;
            internal byte[][] data;
            private bool m_isVersion6;

            internal PubMethod(PgpPublicKey pubKey, bool sessionKeyObfuscation)
            {
                this.pubKey = pubKey;
                this.sessionKeyObfuscation = sessionKeyObfuscation;
            }

            public override void AddSessionInfo(
                byte[] sessionInfo,
                SecureRandom random)
            {
                byte[] encryptedSessionInfo = EncryptSessionInfo(sessionInfo, random);

                this.data = ProcessSessionInfo(encryptedSessionInfo);
            }

            /// <summary>Protect the session key for a v2 SEIPD message: a version 6 PKESK packet (RFC 9580 5.1).</summary>
            public override void AddSessionKey(byte[] sessionKey, SymmetricKeyAlgorithmTag payloadAlgorithm,
                AeadAlgorithmTag aeadAlgorithm, SecureRandom random)
            {
                m_isVersion6 = true;

                var cryptoPublicKey = pubKey.GetKey();
                switch (pubKey.Algorithm)
                {
                case PublicKeyAlgorithmTag.X25519:
                case PublicKeyAlgorithmTag.X448:
                    // there is no algorithm octet in a version 6 PKESK
                    data = new byte[1][]{ PgpXdhKem.ForAlgorithm(pubKey.Algorithm).Encrypt(cryptoPublicKey, sessionKey,
                        isVersion3Pkesk: false, payloadAlgorithm, random) };
                    break;
                case PublicKeyAlgorithmTag.MLKem768_X25519:
                case PublicKeyAlgorithmTag.MLKem1024_X448:
                    data = new byte[1][]{ EncryptComposite(pubKey.Algorithm, cryptoPublicKey, sessionKey,
                        isVersion3Pkesk: false, 0, random) };
                    break;
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.ECDH:
                {
                    // the session key followed by its 2-octet checksum, without the algorithm octet
                    int check = 0;
                    for (int i = 0; i < sessionKey.Length; ++i)
                    {
                        check += sessionKey[i];
                    }
                    byte[] sessionInfo = Arrays.Concatenate(sessionKey,
                        new byte[]{ (byte)(check >> 8), (byte)check });
                    try
                    {
                        data = ProcessSessionInfo(EncryptSessionInfo(sessionInfo, random));
                    }
                    finally
                    {
                        Arrays.ZeroMemory(sessionInfo);
                    }
                    break;
                }
                default:
                    throw new PgpException("public key algorithm not supported for AEAD encrypted messages: "
                        + pubKey.Algorithm);
                }
            }

            /// <summary>
            /// RFC 9980 4.2.3: ecdhCipherText || mlkemCipherText || len(C, [symAlgId]) || [symAlgId] || C, where
            /// C is the session key (without checksum or padding) wrapped with AES-256 under the composite KEK.
            /// The algorithm octet is only present in version 3 PKESK packets.
            /// </summary>
            private static byte[] EncryptComposite(PublicKeyAlgorithmTag algorithm, AsymmetricKeyParameter key,
                byte[] sessionKey, bool isVersion3Pkesk, byte symAlgorithm, SecureRandom random)
            {
                AsymmetricKeyParameter ecdhKey;
                MLKemPublicKeyParameters mlKemKey;
                if (key is MLKem768X25519PublicKeyParameters key768)
                {
                    ecdhKey = key768.X25519Key;
                    mlKemKey = key768.MLKemKey;
                }
                else if (key is MLKem1024X448PublicKeyParameters key1024)
                {
                    ecdhKey = key1024.X448Key;
                    mlKemKey = key1024.MLKemKey;
                }
                else
                {
                    throw new PgpException("unknown key class");
                }

                byte[] kek = null;
                try
                {
                    kek = PgpCompositeKem.ForAlgorithm(algorithm).Encapsulate(ecdhKey, mlKemKey, random,
                        out byte[] ecdhCipherText, out byte[] mlkemCipherText);

                    IWrapper wrapper = PgpUtilities.CreateWrapper(SymmetricKeyAlgorithmTag.Aes256);
                    wrapper.Init(true, new ParametersWithRandom(new KeyParameter(kek), random));
                    byte[] wrapped = wrapper.Wrap(sessionKey, 0, sessionKey.Length);

                    byte[] lengthAndAlgorithm = isVersion3Pkesk
                        ? new byte[]{ (byte)(1 + wrapped.Length), symAlgorithm }
                        : new byte[]{ (byte)wrapped.Length };

                    return Arrays.ConcatenateAll(ecdhCipherText, mlkemCipherText, lengthAndAlgorithm, wrapped);
                }
                finally
                {
                    if (kek != null)
                    {
                        Arrays.ZeroMemory(kek);
                    }
                }
            }

            private byte[] EncryptSessionInfo(byte[] sessionInfo, SecureRandom random)
            {
                var cryptoPublicKey = pubKey.GetKey();

                if (pubKey.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519 ||
                    pubKey.Algorithm == PublicKeyAlgorithmTag.MLKem1024_X448)
                {
                    // sessionInfo is algorithm || session key || 2-octet checksum, and is shared between methods
                    byte[] key = Arrays.CopyOfRange(sessionInfo, 1, sessionInfo.Length - 2);
                    try
                    {
                        return EncryptComposite(pubKey.Algorithm, cryptoPublicKey, key, isVersion3Pkesk: true,
                            sessionInfo[0], random);
                    }
                    finally
                    {
                        Arrays.ZeroMemory(key);
                    }
                }

                if (pubKey.Algorithm == PublicKeyAlgorithmTag.X25519 || pubKey.Algorithm == PublicKeyAlgorithmTag.X448)
                {
                    // sessionInfo is algorithm || session key || 2-octet checksum, and is shared between methods
                    byte[] sessionKey = Arrays.CopyOfRange(sessionInfo, 1, sessionInfo.Length - 2);
                    try
                    {
                        return PgpXdhKem.ForAlgorithm(pubKey.Algorithm).Encrypt(cryptoPublicKey, sessionKey,
                            isVersion3Pkesk: true, (SymmetricKeyAlgorithmTag)sessionInfo[0], random);
                    }
                    finally
                    {
                        Arrays.ZeroMemory(sessionKey);
                    }
                }

                if (pubKey.Algorithm != PublicKeyAlgorithmTag.ECDH)
                {
                    IBufferedCipher c;
                    switch (pubKey.Algorithm)
                    {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        c = CipherUtilities.GetCipher("RSA//PKCS1Padding");
                        break;
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        c = CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                        break;
                    case PublicKeyAlgorithmTag.Dsa:
                        throw new PgpException("Can't use DSA for encryption.");
                    case PublicKeyAlgorithmTag.ECDsa:
                        throw new PgpException("Can't use ECDSA for encryption.");
                    case PublicKeyAlgorithmTag.EdDsa_Legacy:
                        throw new PgpException("Can't use EdDSA for encryption.");
                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + pubKey.Algorithm);
                    }

                    c.Init(true, new ParametersWithRandom(cryptoPublicKey, random));
                    return c.DoFinal(sessionInfo);
                }

                ECDHPublicBcpgKey ecPubKey = (ECDHPublicBcpgKey)pubKey.PublicKeyPacket.Key;
                var curveOid = ecPubKey.CurveOid;

                if (EdECObjectIdentifiers.id_X25519.Equals(curveOid) ||
                    CryptlibObjectIdentifiers.curvey25519.Equals(curveOid))
                {
                    X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
                    gen.Init(new X25519KeyGenerationParameters(random));

                    AsymmetricCipherKeyPair ephKp = gen.GenerateKeyPair();

                    X25519Agreement agreement = new X25519Agreement();
                    agreement.Init(ephKp.Private);

                    byte[] secret = new byte[agreement.AgreementSize];
                    agreement.CalculateAgreement(cryptoPublicKey, secret, 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    Span<byte> ephPubEncoding = stackalloc byte[1 + X25519PublicKeyParameters.KeySize];
                    ((X25519PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding[1..]);
#else
                    byte[] ephPubEncoding = new byte[1 + X25519PublicKeyParameters.KeySize];
                    ((X25519PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding, 1);
#endif
                    ephPubEncoding[0] = 0x40;

                    return EncryptSessionInfo(ecPubKey, sessionInfo, secret, ephPubEncoding, random);
                }
                else if (EdECObjectIdentifiers.id_X448.Equals(curveOid))
                {
                    X448KeyPairGenerator gen = new X448KeyPairGenerator();
                    gen.Init(new X448KeyGenerationParameters(random));

                    AsymmetricCipherKeyPair ephKp = gen.GenerateKeyPair();

                    X448Agreement agreement = new X448Agreement();
                    agreement.Init(ephKp.Private);

                    byte[] secret = new byte[agreement.AgreementSize];
                    agreement.CalculateAgreement(cryptoPublicKey, secret, 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    Span<byte> ephPubEncoding = stackalloc byte[1 + X448PublicKeyParameters.KeySize];
                    ((X448PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding[1..]);
#else
                    byte[] ephPubEncoding = new byte[1 + X448PublicKeyParameters.KeySize];
                    ((X448PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding, 1);
#endif
                    ephPubEncoding[0] = 0x40;

                    return EncryptSessionInfo(ecPubKey, sessionInfo, secret, ephPubEncoding, random);
                }
                else
                {
                    // Generate the ephemeral key pair
                    ECDomainParameters ecParams = ((ECPublicKeyParameters)cryptoPublicKey).Parameters;
                    ECKeyPairGenerator gen = new ECKeyPairGenerator();
                    gen.Init(new ECKeyGenerationParameters(ecParams, random));

                    AsymmetricCipherKeyPair ephKp = gen.GenerateKeyPair();

                    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                    agreement.Init(ephKp.Private);
                    BigInteger S = agreement.CalculateAgreement(cryptoPublicKey);
                    byte[] secret = BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), S);

                    var q = ((ECPublicKeyParameters)ephKp.Public).Q;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    int encodedLength = q.GetEncodedLength(false);
                    Span<byte> ephPubEncoding = encodedLength <= 512
                        ? stackalloc byte[encodedLength]
                        : new byte[encodedLength];
                    q.EncodeTo(false, ephPubEncoding);
#else
                    byte[] ephPubEncoding = q.GetEncoded(false);
#endif

                    return EncryptSessionInfo(ecPubKey, sessionInfo, secret, ephPubEncoding, random);
                }
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            private byte[] EncryptSessionInfo(ECDHPublicBcpgKey ecPubKey, byte[] sessionInfo, byte[] secret,
                ReadOnlySpan<byte> ephPubEncoding, SecureRandom random)
#else
            private byte[] EncryptSessionInfo(ECDHPublicBcpgKey ecPubKey, byte[] sessionInfo, byte[] secret,
                byte[] ephPubEncoding, SecureRandom random)
#endif
            {
                var key = new KeyParameter(Rfc6637Utilities.CreateKey(pubKey.PublicKeyPacket, secret));

                IWrapper w = PgpUtilities.CreateWrapper(ecPubKey.SymmetricKeyAlgorithm);
                w.Init(true, new ParametersWithRandom(key, random));

                byte[] paddedSessionData = PgpPad.PadSessionData(sessionInfo, sessionKeyObfuscation);

                byte[] C = w.Wrap(paddedSessionData, 0, paddedSessionData.Length);
                byte[] VB = new MPInteger(new BigInteger(1, ephPubEncoding)).GetEncoded();

                byte[] rv = new byte[VB.Length + 1 + C.Length];

                Array.Copy(VB, 0, rv, 0, VB.Length);
                rv[VB.Length] = (byte)C.Length;
                Array.Copy(C, 0, rv, VB.Length + 1, C.Length);

                return rv;
            }

            private byte[][] ProcessSessionInfo(byte[] encryptedSessionInfo)
            {
                byte[][] data;

                switch (pubKey.Algorithm)
                {
                case PublicKeyAlgorithmTag.MLKem768_X25519:
                case PublicKeyAlgorithmTag.MLKem1024_X448:
                case PublicKeyAlgorithmTag.X25519:
                case PublicKeyAlgorithmTag.X448:
                    data = new byte[1][]{ encryptedSessionInfo };
                    break;
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    data = new byte[1][]{ ConvertToEncodedMpi(encryptedSessionInfo) };
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    int halfLength = encryptedSessionInfo.Length / 2;
                    byte[] b1 = new byte[halfLength];
                    byte[] b2 = new byte[halfLength];

                    Array.Copy(encryptedSessionInfo, 0, b1, 0, halfLength);
                    Array.Copy(encryptedSessionInfo, halfLength, b2, 0, halfLength);

                    data = new byte[2][]{
                    ConvertToEncodedMpi(b1),
                    ConvertToEncodedMpi(b2),
                };
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                    data = new byte[1][]{ encryptedSessionInfo };
                    break;
                default:
                    throw new PgpException("unknown asymmetric algorithm: " + pubKey.Algorithm);
                }

                return data;
            }

            private static byte[] ConvertToEncodedMpi(byte[] encryptedSessionInfo)
            {
                try
                {
                    return new MPInteger(new BigInteger(1, encryptedSessionInfo)).GetEncoded();
                }
                catch (IOException e)
                {
                    throw new PgpException("Invalid MPI encoding: " + e.Message, e);
                }
            }

            public override void Encode(BcpgOutputStream pOut)
            {
                PublicKeyEncSessionPacket packet = m_isVersion6
                    ? PublicKeyEncSessionPacket.CreateV6Packet(pubKey.Version, pubKey.GetFingerprint(),
                        pubKey.Algorithm, data)
                    : PublicKeyEncSessionPacket.CreateV3Packet(pubKey.KeyId, pubKey.Algorithm, data);

                packet.Encode(pOut);
            }
        }

        private const int DefaultChunkSizeOctet = 12;

        private readonly List<EncMethod> methods = new List<EncMethod>();
        // TODO[api] Refuse IDEA, TripleDES and CAST5 for version 1 SEIPD too (RFC 9580 9.3)
        private readonly SymmetricKeyAlgorithmTag defAlgorithm;
        private readonly SecureRandom rand;

        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = CryptoServicesRegistrar.GetSecureRandom();
        }

        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, bool withIntegrityPacket)
        {
            this.defAlgorithm = encAlgorithm;
            this.withIntegrityPacket = withIntegrityPacket;
            this.rand = CryptoServicesRegistrar.GetSecureRandom();
        }

        /// <summary>Existing SecureRandom constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="random">Source of randomness.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, SecureRandom random)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
        }

        /// <summary>Creates a cipher stream which will have an integrity packet associated with it.</summary>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, bool withIntegrityPacket,
            SecureRandom random)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
            this.withIntegrityPacket = withIntegrityPacket;
        }

        /// <summary>Base constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="random">Source of randomness.</param>
        /// <param name="oldFormat">PGP 2.6.x compatibility required.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, SecureRandom random, bool oldFormat)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
            this.oldFormat = oldFormat;
        }

        /// <summary>
        /// Creates a generator for messages protected by AEAD (a version 2 SEIPD packet, RFC 9580 5.13.2), with
        /// version 6 session key packets and a chunk size of 256 KiB.
        /// </summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use; it needs a block size of 128 bits.</param>
        /// <param name="aeadAlgorithm">The AEAD mode to use.</param>
        /// <param name="random">Source of randomness.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, AeadAlgorithmTag aeadAlgorithm,
            SecureRandom random)
            : this(encAlgorithm, aeadAlgorithm, DefaultChunkSizeOctet, random)
        {
        }

        /// <summary>
        /// Creates a generator for messages protected by AEAD (a version 2 SEIPD packet, RFC 9580 5.13.2), with
        /// version 6 session key packets.
        /// </summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use; it needs a block size of 128 bits.</param>
        /// <param name="aeadAlgorithm">The AEAD mode to use.</param>
        /// <param name="chunkSizeOctet">
        /// The chunk size octet (0 to 16): messages are processed in chunks of 2^(chunkSizeOctet + 6) octets.
        /// </param>
        /// <param name="random">Source of randomness.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, AeadAlgorithmTag aeadAlgorithm,
            int chunkSizeOctet, SecureRandom random)
        {
            if (!PgpAead.IsSupportedCipher(encAlgorithm))
                throw new ArgumentException("unsupported symmetric algorithm for AEAD: " + encAlgorithm,
                    nameof(encAlgorithm));
            if (aeadAlgorithm != AeadAlgorithmTag.Eax && aeadAlgorithm != AeadAlgorithmTag.Ocb &&
                aeadAlgorithm != AeadAlgorithmTag.Gcm)
            {
                throw new ArgumentException("unsupported AEAD algorithm: " + aeadAlgorithm, nameof(aeadAlgorithm));
            }
            if (chunkSizeOctet < 0 || chunkSizeOctet > PgpAead.MaxChunkSizeOctet)
                throw new ArgumentOutOfRangeException(nameof(chunkSizeOctet), "must be in the range 0 to 16");

            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
            m_isAead = true;
            m_aeadAlgorithm = aeadAlgorithm;
            m_chunkSizeOctet = chunkSizeOctet;
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2kDigest)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount: 0x60);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8.
        /// </remarks>
        public void AddMethodUtf8(char[] passPhrase, HashAlgorithmTag s2kDigest)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount: 0x60);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public void AddMethodRaw(byte[] rawPassPhrase, HashAlgorithmTag s2kDigest) =>
            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: false, s2kDigest, itCount: 0x60);

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2kDigest, int itCount)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8.
        /// </remarks>
        public void AddMethodUtf8(char[] passPhrase, HashAlgorithmTag s2kDigest, int itCount)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public void AddMethodRaw(byte[] rawPassPhrase, HashAlgorithmTag s2kDigest, int itCount) =>
            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: false, s2kDigest, itCount);

        /// <summary>Add a PBE encryption method to the encrypted object, using Argon2 to derive the key.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier). A fresh salt is generated; the salt of
        /// <paramref name="argon2Template"/> is not used. With a generator for AEAD messages, a version 6 SKESK
        /// packet is written, otherwise a version 4 SKESK packet.
        /// </remarks>
        public void AddMethod(char[] passPhrase, S2k.Argon2Params argon2Template)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, argon2Template);
        }

        /// <summary>Add a PBE encryption method to the encrypted object, using Argon2 to derive the key.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8. See <see cref="AddMethod(char[], S2k.Argon2Params)"/>.
        /// </remarks>
        public void AddMethodUtf8(char[] passPhrase, S2k.Argon2Params argon2Template)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, argon2Template);
        }

        /// <summary>Add a PBE encryption method to the encrypted object, using Argon2 to derive the key.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes. See
        /// <see cref="AddMethod(char[], S2k.Argon2Params)"/>.
        /// </remarks>
        public void AddMethodRaw(byte[] rawPassPhrase, S2k.Argon2Params argon2Template) =>
            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: false, argon2Template);

        private void ImplAddPbeMethod(byte[] rawPassPhrase, bool clearPassPhrase, S2k.Argon2Params argon2Template)
        {
            if (argon2Template == null)
                throw new ArgumentNullException(nameof(argon2Template));

            var argon2Params = new S2k.Argon2Params(argon2Template.Passes, argon2Template.Parallelism,
                argon2Template.MemorySizeExponent, rand);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase, S2k.Argon2S2k(argon2Params));
        }

        internal void ImplAddPbeMethod(byte[] rawPassPhrase, bool clearPassPhrase, HashAlgorithmTag s2kDigest,
            int itCount)
        {
            // RFC 9580 9.5: no S2K with MD5, SHA-1 or RIPEMD-160 in new packets, also in version 4 SKESK packets
            if (PgpUtilities.IsWeakS2kHash(s2kDigest))
                throw new ArgumentException("S2K hash not allowed: " + s2kDigest, nameof(s2kDigest));

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase, S2k.GenerateSaltedAndIterated(rand, s2kDigest, itCount));
        }

        private void ImplAddPbeMethod(byte[] rawPassPhrase, bool clearPassPhrase, S2k s2k)
        {
            var key = PgpUtilities.DoMakeKeyFromPassPhrase(defAlgorithm, s2k, rawPassPhrase, clearPassPhrase);

            if (m_isAead)
            {
                methods.Add(new AeadPbeMethod(defAlgorithm, s2k, key.GetKey()));
                return;
            }

            var encMethod = new PbeMethod(defAlgorithm, s2k, key);
            methods.Add(encMethod);
        }

        /// <summary>Add a public key encrypted session key to the encrypted object.</summary>
        /// <remarks>
        /// For X25519, X448 and the ML-KEM composite keys (RFC 9980), a generator that makes version 1 SEIPD packets
        /// must have been created with an integrity packet and an AES algorithm; AES-256 is recommended. Such a
        /// message uses a v3 PKESK. A generator made with an AEAD algorithm makes v6 PKESK and v2 SEIPD packets.
        /// </remarks>
        public void AddMethod(PgpPublicKey key) => AddMethod(key, sessionKeyObfuscation: true);

        /// <summary>Add a public key encrypted session key to the encrypted object.</summary>
        /// <remarks>
        /// <paramref name="sessionKeyObfuscation"/> only applies to ECDH keys. See
        /// <see cref="AddMethod(PgpPublicKey)"/> for the requirements of X25519, X448 and ML-KEM keys.
        /// </remarks>
        public void AddMethod(PgpPublicKey key, bool sessionKeyObfuscation)
        {
            if (!key.IsEncryptionKey)
                throw new ArgumentException("passed in key not an encryption key!", nameof(key));

            // key material that is not defined for the version of its key, or that cannot be parsed, is kept opaque
            if (key.PublicKeyPacket.Key is UnknownBcpgKey)
            {
                throw new ArgumentException(
                    "the material of this version " + key.Version + " " + key.Algorithm + " key cannot be used",
                    nameof(key));
            }

            CheckVersion6EcdhRecipient(key);

            if (m_isAead)
            {
                CheckAeadRecipient(key);
                methods.Add(new PubMethod(key, sessionKeyObfuscation));
                return;
            }

            if (key.Algorithm == PublicKeyAlgorithmTag.X25519 || key.Algorithm == PublicKeyAlgorithmTag.X448)
            {
                // RFC 9580 5.1.6 and 5.1.7: AES only in a v3 PKESK, and the SED packet must not be generated
                if (!withIntegrityPacket)
                    throw new PgpException(key.Algorithm + " recipients require an integrity protected packet");
                if (defAlgorithm != SymmetricKeyAlgorithmTag.Aes128 &&
                    defAlgorithm != SymmetricKeyAlgorithmTag.Aes192 &&
                    defAlgorithm != SymmetricKeyAlgorithmTag.Aes256)
                {
                    throw new PgpException(key.Algorithm + " recipients require AES-128, AES-192 or AES-256");
                }
            }

            if (key.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519 ||
                key.Algorithm == PublicKeyAlgorithmTag.MLKem1024_X448)
            {
                // RFC 9980 4.3.1: never with the obsolete SED packet, and AES only in a v3 PKESK
                if (!withIntegrityPacket)
                    throw new PgpException(key.Algorithm + " recipients require an integrity protected packet");
                if (defAlgorithm != SymmetricKeyAlgorithmTag.Aes128 &&
                    defAlgorithm != SymmetricKeyAlgorithmTag.Aes192 &&
                    defAlgorithm != SymmetricKeyAlgorithmTag.Aes256)
                {
                    throw new PgpException(key.Algorithm + " recipients require AES-128, AES-192 or AES-256");
                }
            }

            methods.Add(new PubMethod(key, sessionKeyObfuscation));
        }

        /// <summary>The requirements for recipients of version 2 SEIPD messages (RFC 9580 5.1.2, 9.2).</summary>
        private static void CheckAeadRecipient(PgpPublicKey key)
        {
            if (key.Version != PublicKeyPacket.Version4 && key.Version != PublicKeyPacket.Version6)
                throw new PgpException("unsupported recipient key version: " + key.Version);

            switch (key.Algorithm)
            {
            case PublicKeyAlgorithmTag.ElGamalEncrypt:
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                throw new PgpException("ElGamal cannot be used for encryption in AEAD encrypted messages");
            }
        }

        /// <summary>
        /// RFC 9580 11.5.1: no message is encrypted to a version 6 ECDH key that announces other KDF or KEK parameters
        /// than its curve requires, whatever the format of the message.
        /// </summary>
        private static void CheckVersion6EcdhRecipient(PgpPublicKey key)
        {
            if (key.Algorithm != PublicKeyAlgorithmTag.ECDH || key.Version != PublicKeyPacket.Version6)
                return;

            var ecdhKey = (ECDHPublicBcpgKey)key.PublicKeyPacket.Key;
            PgpKdfParameters expected = PgpUtilities.GetMandatedEcdhKdfParameters(ecdhKey.CurveOid);
            if (expected != null &&
                (expected.HashAlgorithm != ecdhKey.HashAlgorithm ||
                 expected.SymmetricWrapAlgorithm != ecdhKey.SymmetricKeyAlgorithm))
            {
                throw new PgpException(
                    "the KDF parameters of the ECDH key are not the ones required for version 6 keys");
            }
        }

        private static void AddCheckSum(byte[] sessionInfo)
        {
            Debug.Assert(sessionInfo != null);
            Debug.Assert(sessionInfo.Length >= 3);

            int check = 0;

            for (int i = 1; i < sessionInfo.Length - 2; i++)
            {
                check += sessionInfo[i];
            }

            sessionInfo[sessionInfo.Length - 2] = (byte)(check >> 8);
            sessionInfo[sessionInfo.Length - 1] = (byte)(check);
        }

        private static byte[] CreateSessionInfo(SymmetricKeyAlgorithmTag algorithm, KeyParameter key)
        {
            int keyLength = key.KeyLength;
            byte[] sessionInfo = new byte[keyLength + 3];
            sessionInfo[0] = (byte)algorithm;
            key.CopyKeyTo(sessionInfo, 1, keyLength);
            AddCheckSum(sessionInfo);
            return sessionInfo;
        }

        /// <summary>
        /// <p>
        /// If buffer is non null stream assumed to be partial, otherwise the length will be used
        /// to output a fixed length packet.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// </summary>
        private Stream Open(Stream outStr, long length, byte[] buffer)
        {
            if (cOut != null || m_aeadOut != null)
                throw new InvalidOperationException("generator already in open state");
            if (methods.Count == 0)
                throw new InvalidOperationException("No encryption methods specified");
            if (outStr == null)
                throw new ArgumentNullException(nameof(outStr));

            if (m_isAead)
                return OpenAead(outStr, length, buffer);

            pOut = new BcpgOutputStream(outStr);

            KeyParameter key;

            if (methods.Count == 1)
            {
                if (methods[0] is PbeMethod pbeMethod)
                {
                    key = pbeMethod.GetKey();
                }
                else if (methods[0] is PubMethod pubMethod)
                {
                    key = PgpUtilities.MakeRandomKey(defAlgorithm, rand);

                    byte[] sessionInfo = CreateSessionInfo(defAlgorithm, key);

                    try
                    {
                        pubMethod.AddSessionInfo(sessionInfo, rand);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }
                    finally
                    {
                        Arrays.ZeroMemory(sessionInfo);
                    }
                }
                else
                {
                    throw new InvalidOperationException();
                }

                methods[0].Encode(pOut);
            }
            else // multiple methods
            {
                key = PgpUtilities.MakeRandomKey(defAlgorithm, rand);
                byte[] sessionInfo = CreateSessionInfo(defAlgorithm, key);

                try
                {
                    foreach (EncMethod m in methods)
                    {
                        try
                        {
                            m.AddSessionInfo(sessionInfo, rand);
                        }
                        catch (Exception e)
                        {
                            throw new PgpException("exception encrypting session key", e);
                        }

                        m.Encode(pOut);
                    }
                }
                finally
                {
                    Arrays.ZeroMemory(sessionInfo);
                }
            }

            string cName = PgpUtilities.GetSymmetricCipherName(defAlgorithm)
                ?? throw new PgpException("null cipher specified");

            try
            {
                if (withIntegrityPacket)
                {
                    cName += "/CFB/NoPadding";
                }
                else
                {
                    cName += "/OpenPGPCFB/NoPadding";
                }

                c = CipherUtilities.GetCipher(cName);

                // TODO Confirm the IV should be all zero bytes (not inLineIv - see below)
                byte[] iv = new byte[c.GetBlockSize()];
                c.Init(true, new ParametersWithRandom(new ParametersWithIV(key, iv), rand));

                if (buffer == null)
                {
                    //
                    // we have to Add block size + 2 for the Generated IV and + 1 + 22 if integrity protected
                    //
                    if (withIntegrityPacket)
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, length + c.GetBlockSize() + 2 + 1 + 22);
                        pOut.WriteByte(1);        // version number
                    }
                    else
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricKeyEncrypted, length + c.GetBlockSize() + 2, oldFormat);
                    }
                }
                else
                {
                    if (withIntegrityPacket)
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, buffer);
                        pOut.WriteByte(1);        // version number
                    }
                    else
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricKeyEncrypted, buffer);
                    }
                }

                int blockSize = c.GetBlockSize();
                byte[] inLineIv = new byte[blockSize + 2];
                rand.NextBytes(inLineIv, 0, blockSize);
                Array.Copy(inLineIv, inLineIv.Length - 4, inLineIv, inLineIv.Length - 2, 2);

                Stream myOut = cOut = new CipherStream(pOut, null, c);

                if (withIntegrityPacket)
                {
                    IDigest digest = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha1);
                    myOut = digestOut = new DigestStream(myOut, null, digest);
                }

                myOut.Write(inLineIv, 0, inLineIv.Length);

                return new WrappedGeneratorStream(this, myOut);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

        /// <summary>
        /// Write the session key packets and the header of the v2 SEIPD packet, and return the stream that encrypts
        /// the data in chunks.
        /// </summary>
        private Stream OpenAead(Stream outStr, long length, byte[] buffer)
        {
            byte[] sessionKey = new byte[SymmetricKeyUtilities.GetKeyLengthInOctets(defAlgorithm)];
            rand.NextBytes(sessionKey);

            byte[][] keyAndIv = null;
            try
            {
                pOut = new BcpgOutputStream(outStr);

                foreach (EncMethod m in methods)
                {
                    try
                    {
                        m.AddSessionKey(sessionKey, defAlgorithm, m_aeadAlgorithm, rand);
                    }
                    catch (PgpException)
                    {
                        throw;
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }

                    m.Encode(pOut);
                }

                byte[] salt = new byte[SymmetricEncIntegrityPacket.SaltLength];
                rand.NextBytes(salt);

                byte[] aad = SymmetricEncIntegrityPacket.CreateAAData(defAlgorithm, m_aeadAlgorithm, m_chunkSizeOctet);
                keyAndIv = PgpAead.DeriveMessageKeyAndIv(defAlgorithm, m_aeadAlgorithm, sessionKey, salt, aad);

                if (buffer == null)
                {
                    // header (version, algorithms, chunk size), salt, the chunks with their tags, and the final tag
                    long chunkLength = PgpAead.GetChunkLength(m_chunkSizeOctet);
                    long chunks = (length + chunkLength - 1) / chunkLength;
                    long bodyLength = 4 + salt.Length + length + chunks * PgpAead.TagLength + PgpAead.TagLength;

                    pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, bodyLength);
                }
                else
                {
                    pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, buffer);
                }

                pOut.Write((byte)SymmetricEncIntegrityPacket.Version2, (byte)defAlgorithm, (byte)m_aeadAlgorithm,
                    (byte)m_chunkSizeOctet);
                pOut.Write(salt);

                m_aeadOut = new PgpAeadOutputStream(pOut, defAlgorithm, m_aeadAlgorithm, keyAndIv[0], keyAndIv[1], aad,
                    m_chunkSizeOctet);

                return new WrappedGeneratorStream(this, m_aeadOut);
            }
            finally
            {
                Arrays.ZeroMemory(sessionKey);
                if (keyAndIv != null)
                {
                    Arrays.ZeroMemory(keyAndIv[0]);
                    Arrays.ZeroMemory(keyAndIv[1]);
                }
            }
        }

        /// <summary>
        /// <p>
        /// Return an output stream which will encrypt the data as it is written to it.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// </summary>
        public Stream Open(Stream outStr, long length) => Open(outStr, length, buffer: null);

        /// <summary>
        /// <p>
        /// Return an output stream which will encrypt the data as it is written to it.
        /// The stream will be written out in chunks according to the size of the passed in buffer.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// <p>
        /// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
        /// bytes worth of the buffer will be used.
        /// </p>
        /// </summary>
        public Stream Open(Stream outStr, byte[] buffer) => Open(outStr, length: 0, buffer);

        [Obsolete("Dispose any opened Stream directly")]
        public void Close()
        {
            if (m_aeadOut != null)
            {
                try
                {
                    m_aeadOut.Finish();
                    pOut.Finish();
                }
                finally
                {
                    m_aeadOut = null;
                    pOut = null;
                }
                return;
            }

            if (cOut != null)
            {
                // TODO Should this all be under the try/catch block?
                if (digestOut != null)
                {
                    //
                    // hand code a mod detection packet
                    //
                    var bOut = new BcpgOutputStream(digestOut, PacketTag.ModificationDetectionCode, length: 20);

                    // For clarity; really only required if using partial body lengths
                    bOut.Finish();
                    bOut.Flush();

                    byte[] dig = DigestUtilities.DoFinal(digestOut.WriteDigest);

                    cOut.Write(dig, 0, dig.Length);
                }

                cOut.Flush();

                try
                {
                    pOut.Write(c.DoFinal());
                    pOut.Finish();
                }
                catch (Exception e)
                {
                    throw new IOException(e.Message, e);
                }

                cOut = null;
                pOut = null;
            }
        }
    }
}
