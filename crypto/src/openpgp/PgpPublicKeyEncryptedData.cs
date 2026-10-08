using System;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A public key encrypted data object.</remarks>
    public class PgpPublicKeyEncryptedData
        : PgpEncryptedData
    {
        private readonly PublicKeyEncSessionPacket m_keyData;

        internal PgpPublicKeyEncryptedData(PublicKeyEncSessionPacket keyData, InputStreamPacket encData)
            : base(encData)
        {
            m_keyData = keyData;
        }

        private static IBufferedCipher GetKeyCipher(PublicKeyAlgorithmTag algorithm)
        {
            try
            {
                switch (algorithm)
                {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    return CipherUtilities.GetCipher("RSA//PKCS1Padding");
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    return CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                default:
                    throw new PgpException("unknown asymmetric algorithm: " + algorithm);
                }
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

        /// <summary>The version of the PKESK packet: 3, or 6 (RFC 9580 5.1).</summary>
        public int Version => m_keyData.Version;

        /// <summary>The version of the key that the session key is encrypted to (version 6 packets only).</summary>
        /// <returns>The key version, or 0 if the packet does not tell (version 3, or an anonymous recipient).</returns>
        public int KeyVersion => m_keyData.KeyVersion;

        /// <summary>The fingerprint of the key that the session key is encrypted to (version 6 packets only).</summary>
        /// <returns>A copy of the fingerprint, or null if the packet does not tell.</returns>
        public byte[] GetKeyFingerprint() => m_keyData.GetKeyFingerprint();

        /// <summary>The Key ID for the key used to encrypt the data.</summary>
        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => m_keyData.KeyId;

        /// <summary>
        /// Return the algorithm code for the symmetric algorithm used to encrypt the data.
        /// </summary>
        public SymmetricKeyAlgorithmTag GetSymmetricAlgorithm(PgpPrivateKey privKey)
        {
            if (m_keyData.Version == PublicKeyEncSessionPacket.Version6)
            {
                // a version 6 PKESK does not contain the algorithm: it is the one of the version 2 SEIPD packet
                if (EncryptedPacket is SymmetricEncIntegrityPacket seipd &&
                    seipd.Version == SymmetricEncIntegrityPacket.Version2)
                {
                    return seipd.CipherAlgorithm;
                }

                throw new PgpException("a version 6 PKESK packet requires a version 2 SEIPD packet");
            }

            byte[] sessionData = RecoverSessionData(privKey);
            try
            {
                return (SymmetricKeyAlgorithmTag)sessionData[0];
            }
            finally
            {
                Arrays.ZeroMemory(sessionData);
            }
        }

        /// <summary>Return the decrypted data stream for the packet.</summary>
        public Stream GetDataStream(PgpPrivateKey privKey)
        {
            if (m_keyData.Version == PublicKeyEncSessionPacket.Version6)
                return GetDataStreamV6(privKey);

            // RFC 9580 10.3.2.1: a v3 PKESK only goes with a v1 SEIPD (or a legacy SED) payload. The PGP encrypted data
            // list discards PKESK packets that precede a v2 SEIPD payload; other versions are not supported.
            Debug.Assert(m_keyData.Version != PublicKeyEncSessionPacket.Version3 || !IsSeipdV2());
            if (IsSeipdOtherVersion())
                throw new PgpException("unsupported SEIPD version");

            // LibrePGP OCB encrypted data (packet type 20) is not an RFC 9580 format; it must not be read as CFB data
            if (EncryptedPacket is AeadEncDataPacket)
                throw new PgpException("unsupported encrypted data: LibrePGP OCB (packet type 20)");

            // RFC 9980 4.3.1: never with the obsolete SED packet
            if ((m_keyData.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519 ||
                m_keyData.Algorithm == PublicKeyAlgorithmTag.MLKem1024_X448) && !IsSeipdV1())
            {
                throw new PgpException("ML-KEM composite algorithms require an integrity protected (v1 SEIPD) payload");
            }
            if ((m_keyData.Algorithm == PublicKeyAlgorithmTag.X25519 || m_keyData.Algorithm == PublicKeyAlgorithmTag.X448)
                && !IsSeipdV1())
            {
                throw new PgpException("X25519 and X448 require an integrity protected (v1 SEIPD) payload");
            }

            byte[] sessionData = RecoverSessionData(privKey);
            try
            {
                return GetDataStream(sessionData);
            }
            finally
            {
                Arrays.ZeroMemory(sessionData);
            }
        }

        /// <summary>Decrypt with the session information of a version 3 PKESK: algorithm, key and checksum.</summary>
        private Stream GetDataStream(byte[] sessionData)
        {
            if (!ConfirmCheckSum(sessionData))
                throw new PgpKeyValidationException("key checksum failed");

            // Algorithm 0 would pass the payload on unencrypted and without the integrity check, for a session key
            // that anybody with the public key can make; no implementation encrypts a message with it
            SymmetricKeyAlgorithmTag symmAlg = (SymmetricKeyAlgorithmTag)sessionData[0];
            if (symmAlg == SymmetricKeyAlgorithmTag.Null)
                throw new PgpException("no symmetric algorithm for the session key");

            string cipherName = PgpUtilities.GetSymmetricCipherName(symmAlg);

            IBufferedCipher cipher;
            try
            {
                cipher = CreateBufferedCipher(cipherName);
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("exception creating cipher", e);
            }

            try
            {
                var key = ParameterUtilities.CreateKeyParameter(cipherName, sessionData, 1, sessionData.Length - 3);

                cipher.Init(forEncryption: false, new ParametersWithIV(key, iv: new byte[cipher.GetBlockSize()]));

                var decStream = InitDecStream(new CipherStream(GetInputStream(), cipher, null));

                byte[] prefix = StreamUtilities.RequireBytes(decStream, cipher.GetBlockSize() + 2);

                /*
                 * The oracle attack on the "quick check" bytes is deemed a security risk for typical public key
                 * encryption usages, therefore we do not perform the check.
                 */
                //QuickCheck(prefix);

                return decStream;
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception starting decryption", e);
            }
        }

        /// <summary>Decrypt a version 2 SEIPD packet with the session key of a version 6 PKESK (RFC 9580 5.1.2).</summary>
        private Stream GetDataStreamV6(PgpPrivateKey privKey)
        {
            if (!IsSeipdV2())
                throw new PgpException("a version 6 PKESK packet requires a version 2 SEIPD packet");

            var seipd = (SymmetricEncIntegrityPacket)EncryptedPacket;

            byte[] sessionKey = RecoverSessionKey(privKey);
            try
            {
                // the session key is for the cipher of the SEIPD packet
                if (!PgpAead.IsSupportedCipher(seipd.CipherAlgorithm))
                    throw new PgpException("unsupported symmetric algorithm in SEIPD packet: " + seipd.CipherAlgorithm);

                if (sessionKey.Length != SymmetricKeyUtilities.GetKeyLengthInOctets(seipd.CipherAlgorithm))
                    throw new PgpException(DecryptionFailureMessage);

                return InitAeadDecStream(sessionKey);
            }
            finally
            {
                Arrays.ZeroMemory(sessionKey);
            }
        }

        private const string DecryptionFailureMessage = "exception decrypting session key";

        /// <summary>
        /// Recover the session key of a version 6 PKESK packet, which has neither an algorithm octet nor, except for
        /// the algorithms that use it, a checksum. Every failure is reported with the same exception, to avoid acting
        /// as a decryption oracle (RFC 9580 13.5).
        /// </summary>
        private byte[] RecoverSessionKey(PgpPrivateKey privKey)
        {
            byte[] plaintext = null;
            try
            {
                if (m_keyData.IsMalformed || !IsMatchingKey(privKey))
                    throw new InvalidOperationException();

                byte[][] fields = m_keyData.GetEncSessionKey();

                switch (m_keyData.Algorithm)
                {
                case PublicKeyAlgorithmTag.X25519:
                case PublicKeyAlgorithmTag.X448:
                    return DecryptXdh(privKey, m_keyData.Algorithm, fields[0], isVersion3Pkesk: false, out _);
                case PublicKeyAlgorithmTag.MLKem768_X25519:
                case PublicKeyAlgorithmTag.MLKem1024_X448:
                    return RecoverKeyComposite(privKey, m_keyData.Algorithm, fields[0], isVersion3Pkesk: false, out _);
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                case PublicKeyAlgorithmTag.ECDH:
                {
                    // the session key followed by its 2-octet checksum
                    plaintext = DoRecoverSessionData(privKey);
                    if (plaintext.Length < 2 + 1)
                        throw new InvalidOperationException();

                    int check = 0;
                    for (int i = 0; i < plaintext.Length - 2; ++i)
                    {
                        check += plaintext[i];
                    }
                    if (Pack.BE_To_UInt16(plaintext, plaintext.Length - 2) != (ushort)check)
                        throw new InvalidOperationException();

                    return Arrays.CopyOfRange(plaintext, 0, plaintext.Length - 2);
                }
                default:
                    throw new InvalidOperationException();
                }
            }
            catch (Exception)
            {
                throw new PgpException(DecryptionFailureMessage);
            }
            finally
            {
                if (plaintext != null)
                {
                    Arrays.ZeroMemory(plaintext);
                }
            }
        }

        /// <summary>
        /// RFC 9980 4.2.4: the algorithm of the PKESK has to be the one of the private key, which also has to have
        /// the expected type.
        /// </summary>
        private bool IsMatchingKey(PgpPrivateKey privKey)
        {
            PublicKeyAlgorithmTag keyAlgorithm = privKey.PublicKeyPacket.Algorithm;

            switch (m_keyData.Algorithm)
            {
            case PublicKeyAlgorithmTag.RsaEncrypt:
            case PublicKeyAlgorithmTag.RsaGeneral:
                return (keyAlgorithm == PublicKeyAlgorithmTag.RsaEncrypt
                    || keyAlgorithm == PublicKeyAlgorithmTag.RsaGeneral) && privKey.Key is RsaKeyParameters;
            case PublicKeyAlgorithmTag.ElGamalEncrypt:
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                return (keyAlgorithm == PublicKeyAlgorithmTag.ElGamalEncrypt
                    || keyAlgorithm == PublicKeyAlgorithmTag.ElGamalGeneral) && privKey.Key is ElGamalPrivateKeyParameters;
            case PublicKeyAlgorithmTag.ECDH:
                return keyAlgorithm == PublicKeyAlgorithmTag.ECDH;
            case PublicKeyAlgorithmTag.X25519:
                return keyAlgorithm == PublicKeyAlgorithmTag.X25519 && privKey.Key is X25519PrivateKeyParameters;
            case PublicKeyAlgorithmTag.X448:
                return keyAlgorithm == PublicKeyAlgorithmTag.X448 && privKey.Key is X448PrivateKeyParameters;
            case PublicKeyAlgorithmTag.MLKem768_X25519:
                return keyAlgorithm == PublicKeyAlgorithmTag.MLKem768_X25519
                    && privKey.Key is MLKem768X25519PrivateKeyParameters;
            case PublicKeyAlgorithmTag.MLKem1024_X448:
                return keyAlgorithm == PublicKeyAlgorithmTag.MLKem1024_X448
                    && privKey.Key is MLKem1024X448PrivateKeyParameters;
            default:
                return false;
            }
        }

        private byte[] RecoverSessionData(PgpPrivateKey privKey)
        {
            try
            {
                return DoRecoverSessionData(privKey);
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                // e.g. a key that does not match the PKESK algorithm, or a failed key unwrap
                throw new PgpException("exception decrypting session key", e);
            }
        }

        private byte[] DoRecoverSessionData(PgpPrivateKey privKey)
        {
            byte[][] secKeyData = m_keyData.GetEncSessionKey();

            // These return the session information in the layout of a version 3 PKESK: algorithm, key, checksum
            if (m_keyData.Version == PublicKeyEncSessionPacket.Version3)
            {
                if (m_keyData.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519 ||
                    m_keyData.Algorithm == PublicKeyAlgorithmTag.MLKem1024_X448)
                {
                    return RecoverSessionDataComposite(privKey, m_keyData.Algorithm, secKeyData[0]);
                }

                if (m_keyData.Algorithm == PublicKeyAlgorithmTag.X25519 ||
                    m_keyData.Algorithm == PublicKeyAlgorithmTag.X448)
                {
                    return RecoverSessionDataXdh(privKey, m_keyData.Algorithm, secKeyData[0]);
                }
            }

            if (m_keyData.Algorithm != PublicKeyAlgorithmTag.ECDH)
            {
                IBufferedCipher cipher = GetKeyCipher(m_keyData.Algorithm);

                try
                {
                    cipher.Init(forEncryption: false, privKey.Key);
                }
                catch (InvalidKeyException e)
                {
                    throw new PgpException("error setting asymmetric cipher", e);
                }

                if (m_keyData.Algorithm == PublicKeyAlgorithmTag.RsaEncrypt ||
                    m_keyData.Algorithm == PublicKeyAlgorithmTag.RsaGeneral)
                {
                    byte[] bi = secKeyData[0];

                    cipher.ProcessBytes(bi, 2, bi.Length - 2);
                }
                else
                {
                    ElGamalPrivateKeyParameters k = (ElGamalPrivateKeyParameters)privKey.Key;
                    int size = (k.Parameters.P.BitLength + 7) / 8;

                    ProcessEncodedMpi(cipher, size, secKeyData[0]);
                    ProcessEncodedMpi(cipher, size, secKeyData[1]);
                }

                try
                {
                    return cipher.DoFinal();
                }
                catch (Exception e)
                {
                    throw new PgpException("exception decrypting secret key", e);
                }
            }

            ECDHPublicBcpgKey ecPubKey = (ECDHPublicBcpgKey)privKey.PublicKeyPacket.Key;
            byte[] enc = secKeyData[0];

            int pLen = (Pack.BE_To_UInt16(enc, 0) + 7) / 8;
            if ((2 + pLen + 1) > enc.Length)
                throw new PgpException("encoded length out of range");

            byte[] pEnc = new byte[pLen];
            Array.Copy(enc, 2, pEnc, 0, pLen);

            int keyLen = enc[pLen + 2];
            if ((2 + pLen + 1 + keyLen) > enc.Length)
                throw new PgpException("encoded length out of range");

            // RFC 9580 5.1: nothing follows the wrapped session key in a version 6 packet
            // TODO[api] Also in version 3 packets
            if (m_keyData.Version == PublicKeyEncSessionPacket.Version6 && 2 + pLen + 1 + keyLen != enc.Length)
                throw new PgpException("encoded length out of range");

            byte[] keyEnc = new byte[keyLen];
            Array.Copy(enc, 2 + pLen + 1, keyEnc, 0, keyEnc.Length);

            var curveOid = ecPubKey.CurveOid;
            byte[] secret;

            if (EdECObjectIdentifiers.id_X25519.Equals(curveOid) ||
                CryptlibObjectIdentifiers.curvey25519.Equals(curveOid))
            {
                // skip the 0x40 header byte.
                if (pEnc.Length != (1 + X25519PublicKeyParameters.KeySize) || 0x40 != pEnc[0])
                    throw new ArgumentException("Invalid X25519 public key");

                X25519PublicKeyParameters ephPub = new X25519PublicKeyParameters(pEnc, 1);

                X25519Agreement agreement = new X25519Agreement();
                agreement.Init(privKey.Key);

                secret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(ephPub, secret, 0);
            }
            else if (EdECObjectIdentifiers.id_X448.Equals(curveOid))
            {
                // skip the 0x40 header byte.
                if (pEnc.Length != (1 + X448PublicKeyParameters.KeySize) || 0x40 != pEnc[0])
                    throw new ArgumentException("Invalid X448 public key");

                X448PublicKeyParameters ephPub = new X448PublicKeyParameters(pEnc, 1);

                X448Agreement agreement = new X448Agreement();
                agreement.Init(privKey.Key);

                secret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(ephPub, secret, 0);
            }
            else
            {
                ECDomainParameters ecParameters = ((ECPrivateKeyParameters)privKey.Key).Parameters;

                ECPublicKeyParameters ephPub = new ECPublicKeyParameters(ecParameters.Curve.DecodePoint(pEnc),
                    ecParameters);

                ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                agreement.Init(privKey.Key);
                BigInteger S = agreement.CalculateAgreement(ephPub);
                secret = BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), S);
            }

            KeyParameter key = new KeyParameter(Rfc6637Utilities.CreateKey(privKey.PublicKeyPacket, secret));

            IWrapper wrapper = PgpUtilities.CreateWrapper(ecPubKey.SymmetricKeyAlgorithm);
            wrapper.Init(forWrapping: false, key);

            return PgpPad.UnpadSessionData(wrapper.Unwrap(keyEnc, 0, keyEnc.Length));
        }

        /// <summary>
        /// Recover the session key from a v3 PKESK for an X25519 or X448 key (RFC 9580 5.1.6, 5.1.7) and return it in
        /// the same layout as the other algorithms: algorithm || session key || 2-octet checksum.
        /// </summary>
        /// <remarks>Every failure is reported with the same exception (RFC 9580 13.5).</remarks>
        private static byte[] RecoverSessionDataXdh(PgpPrivateKey privKey, PublicKeyAlgorithmTag algorithm,
            byte[] fields)
        {
            byte[] sessionKey = null;
            try
            {
                sessionKey = DecryptXdh(privKey, algorithm, fields, isVersion3Pkesk: true,
                    out SymmetricKeyAlgorithmTag symAlgorithm);

                if (sessionKey.Length != PgpUtilities.GetKeySize(symAlgorithm) / 8)
                    throw new InvalidOperationException();

                return ToSessionData(symAlgorithm, sessionKey);
            }
            catch (Exception)
            {
                throw new PgpException("exception decrypting session key");
            }
            finally
            {
                if (sessionKey != null)
                {
                    Arrays.ZeroMemory(sessionKey);
                }
            }
        }

        private static byte[] DecryptXdh(PgpPrivateKey privKey, PublicKeyAlgorithmTag algorithm, byte[] fields,
            bool isVersion3Pkesk, out SymmetricKeyAlgorithmTag symAlgorithm)
        {
            if (privKey.PublicKeyPacket.Algorithm != algorithm)
                throw new InvalidOperationException();

            byte[] recipientPublicKey;
            if (algorithm == PublicKeyAlgorithmTag.X25519)
            {
                if (!(privKey.Key is X25519PrivateKeyParameters) ||
                    !(privKey.PublicKeyPacket.Key is X25519PublicBcpgKey x25519PublicKey))
                {
                    throw new InvalidOperationException();
                }
                recipientPublicKey = x25519PublicKey.GetKey();
            }
            else
            {
                if (!(privKey.Key is X448PrivateKeyParameters) ||
                    !(privKey.PublicKeyPacket.Key is X448PublicBcpgKey x448PublicKey))
                {
                    throw new InvalidOperationException();
                }
                recipientPublicKey = x448PublicKey.GetKey();
            }

            return PgpXdhKem.ForAlgorithm(algorithm).Decrypt(privKey.Key, recipientPublicKey, fields,
                isVersion3Pkesk, out symAlgorithm);
        }

        /// <summary>The layout of the session information that is shared by the algorithms.</summary>
        private static byte[] ToSessionData(SymmetricKeyAlgorithmTag symAlgorithm, byte[] sessionKey)
        {
            byte[] sessionData = new byte[1 + sessionKey.Length + 2];
            sessionData[0] = (byte)symAlgorithm;
            Array.Copy(sessionKey, 0, sessionData, 1, sessionKey.Length);
            int check = 0;
            for (int i = 0; i < sessionKey.Length; ++i)
            {
                check += sessionKey[i];
            }
            sessionData[sessionData.Length - 2] = (byte)(check >> 8);
            sessionData[sessionData.Length - 1] = (byte)check;
            return sessionData;
        }

        /// <summary>
        /// Recover the session key from a v3 PKESK for an ML-KEM-768+X25519 key (RFC 9980 4.2.4, 4.3.1) and return it
        /// in the same layout as the other algorithms: algorithm || session key || 2-octet checksum.
        /// </summary>
        /// <remarks>
        /// Every failure is reported with the same exception, to avoid acting as a decryption oracle
        /// (RFC 9580 13.5). The checks before decapsulation only depend on public data.
        /// </remarks>
        private static byte[] RecoverSessionDataComposite(PgpPrivateKey privKey, PublicKeyAlgorithmTag algorithm,
            byte[] enc)
        {
            byte[] sessionKey = null;
            try
            {
                sessionKey = RecoverKeyComposite(privKey, algorithm, enc, isVersion3Pkesk: true,
                    out SymmetricKeyAlgorithmTag symAlgorithm);

                if (sessionKey.Length != PgpUtilities.GetKeySize(symAlgorithm) / 8)
                    throw new InvalidOperationException();

                return ToSessionData(symAlgorithm, sessionKey);
            }
            catch (Exception)
            {
                throw new PgpException(DecryptionFailureMessage);
            }
            finally
            {
                if (sessionKey != null)
                {
                    Arrays.ZeroMemory(sessionKey);
                }
            }
        }

        /// <summary>
        /// Recover the raw session key from the fields of a PKESK for a composite ML-KEM key (RFC 9980 4.2.4).
        /// </summary>
        /// <remarks>
        /// The checks before decapsulation only depend on public data. Failures are reported to the callers, which
        /// turn them into the uniform error.
        /// </remarks>
        private static byte[] RecoverKeyComposite(PgpPrivateKey privKey, PublicKeyAlgorithmTag algorithm, byte[] enc,
            bool isVersion3Pkesk, out SymmetricKeyAlgorithmTag symAlgorithm)
        {
            PgpCompositeKem kem = PgpCompositeKem.ForAlgorithm(algorithm);
            int ecdhLength = kem.EcdhCipherTextLength;
            int lengthPos = ecdhLength + kem.MLKemCipherTextLength;

            byte[] kek = null;
            try
            {
                if (privKey.PublicKeyPacket.Algorithm != algorithm)
                    throw new InvalidOperationException();

                AsymmetricKeyParameter ecdhPrivateKey;
                MLKemPrivateKeyParameters mlKemPrivateKey;
                byte[] ecdhPublicKey;
                if (algorithm == PublicKeyAlgorithmTag.MLKem768_X25519)
                {
                    if (!(privKey.Key is MLKem768X25519PrivateKeyParameters privateKey) ||
                        !(privKey.PublicKeyPacket.Key is MLKem768X25519PublicBcpgKey publicKey))
                    {
                        throw new InvalidOperationException();
                    }
                    ecdhPrivateKey = privateKey.X25519Key;
                    mlKemPrivateKey = privateKey.MLKemKey;
                    ecdhPublicKey = publicKey.GetX25519PublicKey();
                }
                else
                {
                    if (!(privKey.Key is MLKem1024X448PrivateKeyParameters privateKey) ||
                        !(privKey.PublicKeyPacket.Key is MLKem1024X448PublicBcpgKey publicKey))
                    {
                        throw new InvalidOperationException();
                    }
                    ecdhPrivateKey = privateKey.X448Key;
                    mlKemPrivateKey = privateKey.MLKemKey;
                    ecdhPublicKey = publicKey.GetX448PublicKey();
                }

                // ecdhCipherText || mlkemCipherText || len(C, [symAlgId]) || [symAlgId] || C
                if (enc.Length < lengthPos + 2)
                    throw new InvalidOperationException();

                int length = enc[lengthPos];
                if (lengthPos + 1 + length != enc.Length)
                    throw new InvalidOperationException();

                int wrappedPos = lengthPos + 1;
                symAlgorithm = SymmetricKeyAlgorithmTag.Null;
                if (isVersion3Pkesk)
                {
                    if (length < 1 + 24)
                        throw new InvalidOperationException();

                    symAlgorithm = (SymmetricKeyAlgorithmTag)enc[wrappedPos++];
                    if (symAlgorithm != SymmetricKeyAlgorithmTag.Aes128 &&
                        symAlgorithm != SymmetricKeyAlgorithmTag.Aes192 &&
                        symAlgorithm != SymmetricKeyAlgorithmTag.Aes256)
                    {
                        throw new InvalidOperationException();
                    }
                }
                else if (length < 24)
                {
                    throw new InvalidOperationException();
                }

                int wrappedLength = enc.Length - wrappedPos;
                if ((wrappedLength & 7) != 0)
                    throw new InvalidOperationException();

                kek = kem.Decapsulate(ecdhPrivateKey, mlKemPrivateKey, ecdhPublicKey,
                    Arrays.CopyOfRange(enc, 0, ecdhLength), Arrays.CopyOfRange(enc, ecdhLength, lengthPos));

                IWrapper wrapper = PgpUtilities.CreateWrapper(SymmetricKeyAlgorithmTag.Aes256);
                wrapper.Init(false, new KeyParameter(kek));
                return wrapper.Unwrap(enc, wrappedPos, wrappedLength);
            }
            finally
            {
                if (kek != null)
                {
                    Arrays.ZeroMemory(kek);
                }
            }
        }

        private static bool ConfirmCheckSum(byte[] sessionInfo)
        {
            int check = 0;

            for (int i = 1; i < sessionInfo.Length - 2; ++i)
            {
                check += sessionInfo[i];
            }

            return Pack.BE_To_UInt16(sessionInfo, sessionInfo.Length - 2) == (ushort)check;
        }

        private static void ProcessEncodedMpi(IBufferedCipher cipher, int size, byte[] mpiEnc)
        {
            if (mpiEnc.Length - 2 > size)  // leading Zero? Shouldn't happen but...
            {
                cipher.ProcessBytes(mpiEnc, 3, mpiEnc.Length - 3);
            }
            else
            {
                byte[] tmp = new byte[size];
                Array.Copy(mpiEnc, 2, tmp, tmp.Length - (mpiEnc.Length - 2), mpiEnc.Length - 2);
                cipher.ProcessBytes(tmp, 0, tmp.Length);
            }
        }
    }
}
