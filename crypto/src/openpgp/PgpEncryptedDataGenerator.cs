using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
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
    /// <remarks>Generator for encrypted objects.</remarks>
    public class PgpEncryptedDataGenerator
		: IStreamGenerator
    {
		private BcpgOutputStream	pOut;
        private CipherStream		cOut;
        private AeadOutputStream    aeadOut;
        private IBufferedCipher		c;
        private readonly bool		withIntegrityPacket;
        private readonly bool		oldFormat;
        private DigestStream		digestOut;

		private abstract class EncMethod
            : ContainedPacket
        {
            protected byte[]                    sessionInfo;
            protected SymmetricKeyAlgorithmTag  encAlgorithm;
            protected AeadAlgorithmTag          aeadAlgorithm;
            protected KeyParameter              key;
            protected byte[]                    aeadIv;

            protected EncMethod(PacketTag packetTag)
                : base(packetTag)
            {
            }

            public abstract void AddSessionInfo(byte[] si, SecureRandom random);
        }

        private class PbeMethod
            : EncMethod
        {
            private readonly S2k s2k;
            private readonly int skeskVersion;

            internal PbeMethod(
                SymmetricKeyAlgorithmTag  encAlgorithm,
                AeadAlgorithmTag          aeadAlgorithm,
                S2k                       s2k,
                KeyParameter              key,
                int                       skeskVersion)
                : base(PacketTag.SymmetricKeyEncryptedSessionKey)
            {
                this.encAlgorithm = encAlgorithm;
                this.aeadAlgorithm = aeadAlgorithm;
                this.s2k = s2k;
                this.key = key;
                this.skeskVersion = skeskVersion;
            }

            public KeyParameter GetKey()
            {
                return key;
            }

            private byte[] EncryptSessionInfoForVersion4(byte[] si, SecureRandom random)
            {
                string cName = PgpUtilities.GetSymmetricCipherName(encAlgorithm);
                IBufferedCipher cipher = CipherUtilities.GetCipher($"{cName}/CFB/NoPadding");

                byte[] iv = new byte[cipher.GetBlockSize()];
                cipher.Init(true, new ParametersWithRandom(new ParametersWithIV(key, iv), random));

                return cipher.DoFinal(si, 0, si.Length - 2);
            }

            private byte[] EncryptSessionInfoForVersion6(byte[] si, SecureRandom random)
            {
                byte[] aadata = SymmetricKeyEncSessionPacket.CreateAAData(skeskVersion, encAlgorithm, aeadAlgorithm);

                // key-encryption key derivation
                var hkdfParams = new HkdfParameters(key.GetKey(), Array.Empty<byte>(), aadata);
                var hkdfGen = new HkdfBytesGenerator(PgpUtilities.CreateDigest(HashAlgorithmTag.Sha256));
                hkdfGen.Init(hkdfParams);
                var hkdfOutput = new byte[PgpUtilities.GetKeySizeInOctets(encAlgorithm)];
                hkdfGen.GenerateBytes(hkdfOutput, 0, hkdfOutput.Length);

                BufferedAeadBlockCipher cipher = AeadUtils.CreateAeadCipher(encAlgorithm, aeadAlgorithm);

                aeadIv = new byte[AeadUtils.GetIVLength(aeadAlgorithm)];
                random.NextBytes(aeadIv);

                var aeadParams = new AeadParameters(
                    new KeyParameter(hkdfOutput),
                    8 * AeadUtils.GetAuthTagLength(aeadAlgorithm),
                    aeadIv,
                    aadata);

                cipher.Init(true, aeadParams);
                byte[] keyBytes = cipher.DoFinal(si, 0, si.Length-2);

                return keyBytes;
            }

            public override void AddSessionInfo(
                byte[]			si,
				SecureRandom	random)
            {
                if (skeskVersion == SymmetricKeyEncSessionPacket.Version4)
                {
                    this.sessionInfo = EncryptSessionInfoForVersion4(si, random);
                }
                else if (skeskVersion == SymmetricKeyEncSessionPacket.Version6)
                {
                    this.sessionInfo = EncryptSessionInfoForVersion6(si, random);
                }
            }

			public override void Encode(BcpgOutputStream pOut)
            {
                SymmetricKeyEncSessionPacket pk;
                if (skeskVersion == SymmetricKeyEncSessionPacket.Version6)
                {
                    pk = new SymmetricKeyEncSessionPacket(
                        encAlgorithm, aeadAlgorithm, aeadIv, s2k, sessionInfo);
                }
                else
                {
                    pk = new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, sessionInfo);
                }

				pOut.WritePacket(pk);
            }
        }

		private class PubMethod
            : EncMethod
        {
			internal PgpPublicKey pubKey;
            internal bool sessionKeyObfuscation;
            internal byte[][] data;
            private readonly int pkeskVersion;

            internal PubMethod(PgpPublicKey pubKey, bool sessionKeyObfuscation, int pkeskVersion)
                : base(PacketTag.PublicKeyEncryptedSession)
            {
                this.pubKey = pubKey;
                this.sessionKeyObfuscation = sessionKeyObfuscation;
                this.pkeskVersion = pkeskVersion;
            }

            public override void AddSessionInfo(
                byte[]			sessionInfo,
				SecureRandom	random)
            {
                byte[] encryptedSessionInfo = EncryptSessionInfo(sessionInfo, random);

                this.data = ProcessSessionInfo(encryptedSessionInfo);
            }

            private byte[] EncryptSessionInfo(byte[] sessionInfo, SecureRandom random)
            {
                var cryptoPublicKey = pubKey.GetKey();

                if (pubKey.Algorithm == PublicKeyAlgorithmTag.X25519 || pubKey.Algorithm == PublicKeyAlgorithmTag.X448)
                {
                    IAsymmetricCipherKeyPairGenerator kpGen;
                    IRawAgreement agreement;
                    AsymmetricCipherKeyPair ephemeral;
                    byte[] ephPubEncoding;
                    IDigest digestForHkdf;
                    byte[] hkdfInfo;
                    SymmetricKeyAlgorithmTag wrappingAlgo;

                    if (pubKey.Algorithm == PublicKeyAlgorithmTag.X25519)
                    {
                        agreement = new X25519Agreement();
                        kpGen = new X25519KeyPairGenerator();
                        kpGen.Init(new X25519KeyGenerationParameters(random));
                        digestForHkdf = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha256);
                        hkdfInfo = Encoding.ASCII.GetBytes("OpenPGP X25519");
                        wrappingAlgo = SymmetricKeyAlgorithmTag.Aes128;
                        ephemeral = kpGen.GenerateKeyPair();
                        ephPubEncoding = new byte[X25519PublicKeyParameters.KeySize];
                        ((X25519PublicKeyParameters)ephemeral.Public).Encode(ephPubEncoding, 0);
                    }
                    else
                    {
                        // X448
                        agreement = new X448Agreement();
                        kpGen = new X448KeyPairGenerator();
                        kpGen.Init(new X448KeyGenerationParameters(random));
                        digestForHkdf = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha512);
                        hkdfInfo = Encoding.ASCII.GetBytes("OpenPGP X448");
                        wrappingAlgo = SymmetricKeyAlgorithmTag.Aes256;
                        ephemeral = kpGen.GenerateKeyPair();
                        ephPubEncoding = new byte[X448PublicKeyParameters.KeySize];
                        ((X448PublicKeyParameters)ephemeral.Public).Encode(ephPubEncoding, 0);
                    }

                    agreement.Init(ephemeral.Private);
                    byte[] sharedSecret = new byte[agreement.AgreementSize];
                    agreement.CalculateAgreement(cryptoPublicKey, sharedSecret, 0);

                    byte[] pubKeyMaterial = ((OctetArrayBcpgKey)pubKey.PublicKeyPacket.Key).GetKey();
                    byte[] ikm = Arrays.ConcatenateAll(ephPubEncoding, pubKeyMaterial, sharedSecret);
                    byte[] hkdfSalt = Array.Empty<byte>();
                    var hkdfParams = new HkdfParameters(ikm, hkdfSalt, hkdfInfo);
                    var hkdfGen = new HkdfBytesGenerator(digestForHkdf);
                    hkdfGen.Init(hkdfParams);
                    var hkdfOutput = new byte[PgpUtilities.GetKeySizeInOctets(wrappingAlgo)];
                    hkdfGen.GenerateBytes(hkdfOutput, 0, hkdfOutput.Length);
                    
                    KeyParameter kek = ParameterUtilities.CreateKeyParameter("AES", hkdfOutput);
                    var wrapper = PgpUtilities.CreateWrapper(wrappingAlgo);
                    wrapper.Init(true, kek);

                    int offset = 0; 
                    int length = sessionInfo.Length - 2; // no checksum for X25519 and X448 keys
                    // for X25519 and X448 keys the SymmetricKeyAlgorithmTag, when present (V3 PKESK)
                    // is not encrypted, is prepended to the ESK in plaintext
                    if (pkeskVersion == PublicKeyEncSessionPacket.Version3)
                    {
                        offset = 1;
                        length--;
                    }
                    var keyBytes = wrapper.Wrap(sessionInfo, offset, length);

                    byte[] esk;
                    using (var ms = new MemoryStream())
                    {
                        ms.Write(ephPubEncoding, 0, ephPubEncoding.Length);
                        if (pkeskVersion == PublicKeyEncSessionPacket.Version3)
                        {
                            // Unencrypted SymmetricKeyAlgorithmTag (V3 PKESK only)
                            ms.WriteByte(sessionInfo[0]);
                        }
                        ms.Write(keyBytes, 0, keyBytes.Length);
                        esk = ms.ToArray();
                    }

                    return esk;
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
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    data = new byte[1][] { ConvertToEncodedMpi(encryptedSessionInfo) };
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    int halfLength = encryptedSessionInfo.Length / 2;
                    byte[] b1 = new byte[halfLength];
                    byte[] b2 = new byte[halfLength];

                    Array.Copy(encryptedSessionInfo, 0, b1, 0, halfLength);
                    Array.Copy(encryptedSessionInfo, halfLength, b2, 0, halfLength);

                    data = new byte[2][] {
                        ConvertToEncodedMpi(b1),
                        ConvertToEncodedMpi(b2),
                    };
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                    data = new byte[1][]{ encryptedSessionInfo };
                    break;
                case PublicKeyAlgorithmTag.X25519:
                case PublicKeyAlgorithmTag.X448:
                    int ephemeralKeyLen = pubKey.Algorithm == PublicKeyAlgorithmTag.X25519 ? 32 : 56;
                    byte[] ephemeralKey = new byte[ephemeralKeyLen];
                    byte[] encryptedSessionKey = new byte[encryptedSessionInfo.Length - ephemeralKeyLen];
                    Array.Copy(encryptedSessionInfo, 0, ephemeralKey, 0, ephemeralKeyLen);
                    Array.Copy(encryptedSessionInfo, ephemeralKeyLen, encryptedSessionKey, 0, encryptedSessionKey.Length);

                    data = new byte[][] { ephemeralKey, encryptedSessionKey };
                    break;
                default:
                    throw new PgpException("unknown asymmetric algorithm: " + pubKey.Algorithm);
                }

                return data;
            }

            private byte[] ConvertToEncodedMpi(byte[] encryptedSessionInfo)
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
                PublicKeyEncSessionPacket pk;

                if (pkeskVersion == PublicKeyEncSessionPacket.Version6)
                {
                    pk = new PublicKeyEncSessionPacket(pubKey.Version, pubKey.GetFingerprint(), pubKey.Algorithm, data);
                }
                else
                {
                    pk = new PublicKeyEncSessionPacket(pubKey.KeyId, pubKey.Algorithm, data);
                }

                pOut.WritePacket(pk);
            }
        }

        private readonly List<EncMethod> methods = new List<EncMethod>();
        private readonly SymmetricKeyAlgorithmTag defAlgorithm;
        private readonly AeadAlgorithmTag  defAeadAlgorithm;
        private readonly SecureRandom rand;

        private readonly int skeskVersion;
        private readonly int pkeskVersion;
        private readonly int seipdVersion;
        private readonly byte chunkSizeOctet = 6; // 1 << (chunkSize + 6) = 4096

        public PgpEncryptedDataGenerator(
			SymmetricKeyAlgorithmTag encAlgorithm)
            :this(encAlgorithm, CryptoServicesRegistrar.GetSecureRandom(), false, false)
		{
		}

		public PgpEncryptedDataGenerator(
			SymmetricKeyAlgorithmTag	encAlgorithm,
			bool						withIntegrityPacket)
            : this(encAlgorithm, CryptoServicesRegistrar.GetSecureRandom(), false, withIntegrityPacket)
        {
        }

        /// <summary>Existing SecureRandom constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="random">Source of randomness.</param>
        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag	encAlgorithm,
            SecureRandom				random)
            : this(encAlgorithm, random, false, false)
        {
        }

		/// <summary>Creates a cipher stream which will have an integrity packet associated with it.</summary>
        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag	encAlgorithm,
            bool						withIntegrityPacket,
            SecureRandom				random)
            :this(encAlgorithm, random, false, withIntegrityPacket)
        {
        }

        /// <summary>Base constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="random">Source of randomness.</param>
        /// <param name="oldFormat">PGP 2.6.x compatibility required.</param>
        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag	encAlgorithm,
            SecureRandom				random,
            bool						oldFormat)
            :this (encAlgorithm, random, oldFormat, false)
        {
        }

        private PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag encAlgorithm,
            SecureRandom random,
            bool oldFormat,
            bool withIntegrityPacket)
        {
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
            this.defAlgorithm = encAlgorithm;
            this.oldFormat = oldFormat;
            this.withIntegrityPacket = withIntegrityPacket;

            skeskVersion = SymmetricKeyEncSessionPacket.Version4;
            pkeskVersion = PublicKeyEncSessionPacket.Version3;
            seipdVersion = SymmetricEncIntegrityPacket.Version1;
        }


        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm)
            : this(encAlgorithm, aeadAlgorithm, CryptoServicesRegistrar.GetSecureRandom(), false)
        {
        }

        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm,
            SecureRandom random)
            : this(encAlgorithm, aeadAlgorithm, random, false)
        {
        }

        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm,
            SecureRandom random,
            bool oldFormat)
        {
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
            this.defAlgorithm = encAlgorithm;
            this.defAeadAlgorithm = aeadAlgorithm;
            this.oldFormat = oldFormat;
            this.withIntegrityPacket = true;

            skeskVersion = SymmetricKeyEncSessionPacket.Version6;
            pkeskVersion = PublicKeyEncSessionPacket.Version6;
            seipdVersion = SymmetricEncIntegrityPacket.Version2;
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2kDigest)
        {
            DoAddMethod(PgpUtilities.EncodePassPhrase(passPhrase, false), true, s2kDigest);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public void AddMethodUtf8(char[] passPhrase, HashAlgorithmTag s2kDigest)
        {
            DoAddMethod(PgpUtilities.EncodePassPhrase(passPhrase, true), true, s2kDigest);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public void AddMethodRaw(byte[] rawPassPhrase, HashAlgorithmTag s2kDigest)
        {
            DoAddMethod(rawPassPhrase, false, s2kDigest);
        }

        internal void DoAddMethod(byte[] rawPassPhrase, bool clearPassPhrase, HashAlgorithmTag s2kDigest)
        {
            S2k s2k = PgpUtilities.GenerateS2k(s2kDigest, 0x60, rand);

            methods.Add(new PbeMethod(defAlgorithm, defAeadAlgorithm, s2k, PgpUtilities.DoMakeKeyFromPassPhrase(defAlgorithm, s2k, rawPassPhrase, clearPassPhrase), skeskVersion));
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public void AddMethod(char[] passPhrase, S2k.Argon2Parameters argon2Parameters)
        {
            DoAddMethod(PgpUtilities.EncodePassPhrase(passPhrase, false), true, argon2Parameters);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public void AddMethodUtf8(char[] passPhrase, S2k.Argon2Parameters argon2Parameters)
        {
            DoAddMethod(PgpUtilities.EncodePassPhrase(passPhrase, true), true, argon2Parameters);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public void AddMethodRaw(byte[] rawPassPhrase, S2k.Argon2Parameters argon2Parameters)
        {
            DoAddMethod(rawPassPhrase, false, argon2Parameters);
        }

        internal void DoAddMethod(byte[] rawPassPhrase, bool clearPassPhrase, S2k.Argon2Parameters argon2Parameters)
        {
            S2k s2k = new S2k(argon2Parameters);

            methods.Add(
                new PbeMethod(
                    defAlgorithm,
                    defAeadAlgorithm,
                    s2k,
                    PgpUtilities.DoMakeKeyFromPassPhrase(defAlgorithm, s2k, rawPassPhrase, clearPassPhrase),
                    skeskVersion
                ));
        }

        /// <summary>Add a public key encrypted session key to the encrypted object.</summary>
        public void AddMethod(PgpPublicKey key)
        {
            AddMethod(key, true);
        }

        public void AddMethod(PgpPublicKey key, bool sessionKeyObfuscation)
        {
            if (!key.IsEncryptionKey)
            {
                throw new ArgumentException("passed in key not an encryption key!");
            }

            if (pkeskVersion == PublicKeyEncSessionPacket.Version6
                && (key.Algorithm == PublicKeyAlgorithmTag.ElGamalEncrypt || key.Algorithm == PublicKeyAlgorithmTag.ElGamalGeneral))
            {
                throw new PgpException("cannot generate ElGamal v6 PKESK (see https://www.rfc-editor.org/rfc/rfc9580#name-algorithm-specific-fields-fo)");
            }

            methods.Add(new PubMethod(key, sessionKeyObfuscation, pkeskVersion));
        }

        private void AddCheckSum(
            byte[] sessionInfo)
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

		private byte[] CreateSessionInfo(SymmetricKeyAlgorithmTag algorithm, KeyParameter key)
		{
            int keyLength = key.KeyLength;
            int infoLen = keyLength + 2;
            int offset = 0;

            if (seipdVersion == SymmetricEncIntegrityPacket.Version1)
            {
                infoLen++;
                offset = 1;
            }

            byte[] sessionInfo = new byte[infoLen];

            if (seipdVersion == SymmetricEncIntegrityPacket.Version1)
            {
                sessionInfo[0] = (byte)algorithm;
            }
            key.CopyTo(sessionInfo, offset, keyLength);
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
        private Stream Open(
            Stream	outStr,
            long	length,
            byte[]	buffer)
        {
			if (cOut != null || aeadOut != null)
				throw new InvalidOperationException("generator already in open state");
			if (methods.Count == 0)
				throw new InvalidOperationException("No encryption methods specified");
			if (outStr == null)
				throw new ArgumentNullException("outStr");

			pOut = new BcpgOutputStream(outStr);

			KeyParameter key;

			if (methods.Count == 1)
            {
                if (methods[0] is PbeMethod pbeMethod && skeskVersion == SymmetricKeyEncSessionPacket.Version4)
                {
                    // For V4 SKESK, the encrypted session key is optional. If not present, the session key
                    // is derived directly with the S2K algorithm applied to the passphrase
                    key = pbeMethod.GetKey();
                }
                //else if (methods[0] is PubMethod pubMethod)
                else
                {
                    key = PgpUtilities.MakeRandomKey(defAlgorithm, rand);
					byte[] sessionInfo = CreateSessionInfo(defAlgorithm, key);

                    try
                    {
                        methods[0].AddSessionInfo(sessionInfo, rand);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }
                }
                //else
                //{
                //    throw new InvalidOperationException();
                //}

				pOut.WritePacket(methods[0]);
            }
            else // multiple methods
            {
                key = PgpUtilities.MakeRandomKey(defAlgorithm, rand);
				byte[] sessionInfo = CreateSessionInfo(defAlgorithm, key);

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

                    pOut.WritePacket(m);
                }
            }


            if (seipdVersion == SymmetricEncIntegrityPacket.Version2)
            {
                if (buffer == null)
                {
                    int chunkSize = 1 << (chunkSizeOctet + 6);
                    long chunks = ((length + chunkSize - 1) / chunkSize);

                    long outputLength = length
                        + 1     // version
                        + 1     // algo ID
                        + 1     // AEAD algo ID
                        + 1     // chunk size octet
                        + 32    // salt
                        + AeadUtils.GetAuthTagLength(defAeadAlgorithm) * (chunks + 1); // one auth tag for each chunk plus final tag

                    pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, outputLength);
                }
                else
                {
                    pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, buffer);
                }

                pOut.WriteByte(SymmetricEncIntegrityPacket.Version2);
                pOut.WriteByte((byte)defAlgorithm);
                pOut.WriteByte((byte)defAeadAlgorithm);
                pOut.WriteByte((byte)chunkSizeOctet);

                byte[] salt = new byte[32];
                rand.NextBytes(salt);
                pOut.Write(salt);

                var cipher = AeadUtils.CreateAeadCipher(defAlgorithm, defAeadAlgorithm);
                byte[] aadata = SymmetricEncIntegrityPacket.CreateAAData(SymmetricEncIntegrityPacket.Version2, defAlgorithm, defAeadAlgorithm, chunkSizeOctet);

                AeadUtils.DeriveAeadMessageKeyAndIv(
                    key,
                    defAlgorithm,
                    defAeadAlgorithm,
                    salt,
                    aadata,
                    out var messageKey,
                    out var iv);

                aeadOut = new AeadOutputStream(
                    pOut,
                    cipher,
                    messageKey,
                    iv,
                    defAlgorithm,
                    defAeadAlgorithm,
                    chunkSizeOctet);

                return new WrappedGeneratorStream(this, aeadOut);

            }

            string cName = PgpUtilities.GetSymmetricCipherName(defAlgorithm);
			if (cName == null)
                throw new PgpException("null cipher specified");

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
		/// <p>
		/// Return an output stream which will encrypt the data as it is written to it.
		/// </p>
		/// <p>
		/// The stream created can be closed off by either calling Close()
		/// on the stream or Close() on the generator. Closing the returned
		/// stream does not close off the Stream parameter <c>outStr</c>.
		/// </p>
		/// </summary>
        public Stream Open(
            Stream	outStr,
            long	length)
        {
            return Open(outStr, length, null);
        }

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
        public Stream Open(
            Stream	outStr,
            byte[]	buffer)
        {
            return Open(outStr, 0, buffer);
        }

        [Obsolete("Dispose any opened Stream directly")]
        public void Close()
        {
            if(aeadOut != null)
            {
                aeadOut.Close();
                pOut.Finish();

                aeadOut = null;
                pOut = null;
            }
            if (cOut != null)
            {
				// TODO Should this all be under the try/catch block?
                if (digestOut != null)
                {
                    //
                    // hand code a mod detection packet
                    //
                    BcpgOutputStream bOut = new BcpgOutputStream(
						digestOut, PacketTag.ModificationDetectionCode, 20);

                    bOut.Flush();
                    digestOut.Flush();

					// TODO
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
