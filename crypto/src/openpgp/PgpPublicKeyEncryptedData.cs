using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.EdEC;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A public key encrypted data object.</remarks>
    public class PgpPublicKeyEncryptedData
        : PgpEncryptedData
    {
        private PublicKeyEncSessionPacket keyData;

		internal PgpPublicKeyEncryptedData(
            PublicKeyEncSessionPacket	keyData,
            InputStreamPacket			encData)
            : base(encData)
        {
            this.keyData = keyData;
            EnforceConstraints();
        }

        private void EnforceConstraints()
        {
            switch (keyData.Version)
            {
                case PublicKeyEncSessionPacket.Version3:
                    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-3-public-key-encryp
                    // A version 3 PKESK packet precedes a version 1 SEIPD packet. In historic data, it is sometimes
                    // found preceding a deprecated SED packet.
                    // A V3 PKESK packet MUST NOT precede a V2 SEIPD packet.
                    if (encData is SymmetricEncDataPacket)
                    {
                        return;
                    }
                    if (encData is SymmetricEncIntegrityPacket seipd1)
                    {
                        if (seipd1.Version == SymmetricEncIntegrityPacket.Version1)
                        {
                            return;
                        }
                        throw new ArgumentException($"Version 3 PKESK cannot precede SEIPD of version {seipd1.Version}");
                    }
                    break;

                case PublicKeyEncSessionPacket.Version6:
                    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-6-public-key-encryp
                    //A version 6 PKESK packet precedes a version 2 SEIPD packet.
                    //A V6 PKESK packet MUST NOT precede a V1 SEIPD packet or a deprecated SED packet.
                    if (encData is SymmetricEncDataPacket)
                    {
                        throw new ArgumentException("Version 6 PKESK MUST NOT precede a deprecated SED packet.");
                    }

                    if (encData is SymmetricEncIntegrityPacket seipd2)
                    {
                        if (seipd2.Version == SymmetricEncIntegrityPacket.Version2)
                        {
                            return;
                        }
                        throw new ArgumentException($"Version 6 PKESK cannot precede SEIPD of version {seipd2.Version}");
                    }
                    break;
                default:
                    throw new UnsupportedPacketVersionException($"Unsupported PGP public key encrypted session key packet version encountered: {keyData.Version}");
            }
        }

        private static IBufferedCipher GetKeyCipher(
            PublicKeyAlgorithmTag algorithm)
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

		private bool ConfirmCheckSum(
            byte[] sessionInfo)
        {
            // for X25519 and X448 no checksum or padding are appended to the session key before key wrapping
            if (keyData.Algorithm == PublicKeyAlgorithmTag.X25519 || keyData.Algorithm == PublicKeyAlgorithmTag.X448)
            {
                return true;
            }

            int check = 0;
            for (int i = 1; i != sessionInfo.Length - 2; i++)
            {
                check += sessionInfo[i] & 0xff;
            }

			return (sessionInfo[sessionInfo.Length - 2] == (byte)(check >> 8))
                && (sessionInfo[sessionInfo.Length - 1] == (byte)(check));
        }

		/// <summary>The key ID for the key used to encrypt the data.</summary>
        public long KeyId
        {
			get { return keyData.KeyId; }
        }

        /// <summary>The key fingerprint for the key used to encrypt the data (v6 only).</summary>
        public byte[] GetKeyFingerprint()
        {
            return keyData.GetKeyFingerprint();
        }

        /// <summary>
        /// Return the algorithm code for the symmetric algorithm used to encrypt the data.
        /// </summary>
        public SymmetricKeyAlgorithmTag GetSymmetricAlgorithm(
            PgpPrivateKey privKey)
        {
            if (keyData.Version == PublicKeyEncSessionPacket.Version3)
            {
                // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-fields-for-
                // In V3 PKESK, the symmetric algorithm Id
                //     * with X25519 and X448 is not encrypted, it's prepended in plaintext
                //       to the encrypted session key.
                //     * with other algorithms, it's is encrypted with the session key

                if (keyData.Algorithm == PublicKeyAlgorithmTag.X25519 || keyData.Algorithm == PublicKeyAlgorithmTag.X448)
                {
                    byte[][] secKeyData = keyData.GetEncSessionKey();
                    return (SymmetricKeyAlgorithmTag)secKeyData[1][0];
                }
                else
                {
                    byte[] sessionData = RecoverSessionData(privKey);

                    return (SymmetricKeyAlgorithmTag)sessionData[0];
                }
            }
            else if (keyData.Version == PublicKeyEncSessionPacket.Version6)
            {
                // V6 PKESK stores the cipher algorithm in the V2 SEIPD packet fields.
                return ((SymmetricEncIntegrityPacket)encData).CipherAlgorithm;
            }
            else
            {
                throw new UnsupportedPacketVersionException($"Unsupported PGP public key encrypted session key packet version encountered: {keyData.Version}");
            }
        }

        private Stream GetDataStreamSeipdVersion2(byte[] sessionData, SymmetricEncIntegrityPacket seipd)
        {
            var encAlgo = seipd.CipherAlgorithm;
            var aeadAlgo = seipd.AeadAlgorithm;
            var aadata = seipd.GetAAData();
            var salt = seipd.GetSalt();

            // no checksum and padding for X25519 and X448
            int length = sessionData.Length;
            if (keyData.Algorithm != PublicKeyAlgorithmTag.X25519 && keyData.Algorithm != PublicKeyAlgorithmTag.X448)
            {
                length -= 2;
            }

            var sessionKey = ParameterUtilities.CreateKeyParameter(
                PgpUtilities.GetSymmetricCipherName(encAlgo),
                sessionData, 0, length);

            AeadUtils.DeriveAeadMessageKeyAndIv(sessionKey, encAlgo, aeadAlgo, salt, aadata, out var messageKey, out var iv);
            var cipher = AeadUtils.CreateAeadCipher(seipd.CipherAlgorithm, seipd.AeadAlgorithm);

            var aeadStream = new AeadInputStream(
                encData.GetInputStream(),
                cipher,
                messageKey,
                iv,
                aeadAlgo,
                seipd.ChunkSize,
                aadata);

            encStream = BcpgInputStream.Wrap(aeadStream);
            return encStream;
        }

        /// <summary>Return the decrypted data stream for the packet.</summary>
        public Stream GetDataStream(
            PgpPrivateKey privKey)
        {
			byte[] sessionData = RecoverSessionData(privKey);

            if (!ConfirmCheckSum(sessionData))
                throw new PgpKeyValidationException("key checksum failed");

            if (keyData.Version == PublicKeyEncSessionPacket.Version6)
            {
                // V6 PKESK + V2 SEIPD
                try
                { 
                    return GetDataStreamSeipdVersion2(sessionData, (SymmetricEncIntegrityPacket)encData);
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

            SymmetricKeyAlgorithmTag symmAlg;
            if (keyData.Algorithm == PublicKeyAlgorithmTag.X25519 || keyData.Algorithm == PublicKeyAlgorithmTag.X448)
            {
                // with X25519 and X448 is not encrypted, the symmetric algorithm Id is
                // prepended in plaintext to the encrypted session key.
                byte[][] secKeyData = keyData.GetEncSessionKey();
                symmAlg = (SymmetricKeyAlgorithmTag)secKeyData[1][0];
            }
            else
            {
                symmAlg = (SymmetricKeyAlgorithmTag)sessionData[0];
            }
            if (symmAlg == SymmetricKeyAlgorithmTag.Null)
                return encData.GetInputStream();

            IBufferedCipher cipher;
			string cipherName = PgpUtilities.GetSymmetricCipherName(symmAlg);
			string cName = cipherName;

            try
            {
                if (encData is SymmetricEncIntegrityPacket)
                {
					cName += "/CFB/NoPadding";
                }
                else
                {
					cName += "/OpenPGPCFB/NoPadding";
                }

                cipher = CipherUtilities.GetCipher(cName);
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
                // no checksum and padding for X25519 and X448
                int offset = 0;
                int length = sessionData.Length;
                if (keyData.Algorithm != PublicKeyAlgorithmTag.X25519 && keyData.Algorithm != PublicKeyAlgorithmTag.X448)
                {
                    offset = 1;
                    length -= 3;
                }

                KeyParameter key = ParameterUtilities.CreateKeyParameter(
                    cipherName, sessionData, offset, length);

                byte[] iv = new byte[cipher.GetBlockSize()];

                cipher.Init(false, new ParametersWithIV(key, iv));

                encStream = BcpgInputStream.Wrap(new CipherStream(encData.GetInputStream(), cipher, null));

				if (encData is SymmetricEncIntegrityPacket)
                {
                    truncStream = new TruncatedStream(encStream);

                    IDigest digest = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha1);

                    encStream = new DigestStream(truncStream, digest, null);
                }

				if (Streams.ReadFully(encStream, iv, 0, iv.Length) < iv.Length)
					throw new EndOfStreamException("unexpected end of stream.");

				int v1 = encStream.ReadByte();
                int v2 = encStream.ReadByte();

				if (v1 < 0 || v2 < 0)
                    throw new EndOfStreamException("unexpected end of stream.");

				// Note: the oracle attack on the "quick check" bytes is deemed
				// a security risk for typical public key encryption usages,
				// therefore we do not perform the check.

//				bool repeatCheckPassed =
//					iv[iv.Length - 2] == (byte)v1
//					&&	iv[iv.Length - 1] == (byte)v2;
//
//				// Note: some versions of PGP appear to produce 0 for the extra
//				// bytes rather than repeating the two previous bytes
//				bool zeroesCheckPassed =
//					v1 == 0
//					&&	v2 == 0;
//
//				if (!repeatCheckPassed && !zeroesCheckPassed)
//				{
//					throw new PgpDataValidationException("quick check failed.");
//				}

				return encStream;
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

        private byte[] RecoverSessionData(PgpPrivateKey privKey)
		{
            byte[][] secKeyData = keyData.GetEncSessionKey();

            if (keyData.Algorithm == PublicKeyAlgorithmTag.X25519 || keyData.Algorithm == PublicKeyAlgorithmTag.X448)
            {
                // See sect. 5.1.6. and 5.1.7 of crypto-refresh for the description of
                // the key derivation algorithm for X25519 and X448 
                //     https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-fields-for-
                //     https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-fields-for-x
                byte[] eph = secKeyData[0];
                byte[] esk = secKeyData[1];

                IRawAgreement agreement;
                IDigest digestForHkdf;
                byte[] hkdfInfo;
                AsymmetricKeyParameter ephPubkey;
                SymmetricKeyAlgorithmTag wrappingAlgo;

                if (keyData.Algorithm == PublicKeyAlgorithmTag.X25519)
                {
                    agreement = new X25519Agreement();
                    ephPubkey = new X25519PublicKeyParameters(eph);
                    digestForHkdf = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha256);
                    hkdfInfo = Encoding.ASCII.GetBytes("OpenPGP X25519");
                    wrappingAlgo = SymmetricKeyAlgorithmTag.Aes128;
                }
                else
                {
                    agreement = new X448Agreement();
                    ephPubkey = new X448PublicKeyParameters(eph);
                    digestForHkdf = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha512);
                    hkdfInfo = Encoding.ASCII.GetBytes("OpenPGP X448");
                    wrappingAlgo = SymmetricKeyAlgorithmTag.Aes256;
                }

                agreement.Init(privKey.Key);
                byte[] sharedSecret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(ephPubkey, sharedSecret, 0);

                byte[] pubKeyMaterial = ((OctetArrayBcpgKey)privKey.PublicKeyPacket.Key).GetKey();
                byte[] ikm = Arrays.ConcatenateAll(eph, pubKeyMaterial, sharedSecret);
                byte[] hkdfSalt = Array.Empty<byte>();
                var hkdfParams = new HkdfParameters(ikm, hkdfSalt, hkdfInfo);
                var hkdfGen = new HkdfBytesGenerator(digestForHkdf);
                hkdfGen.Init(hkdfParams);
                var hkdfOutput = new byte[PgpUtilities.GetKeySizeInOctets(wrappingAlgo)];
                hkdfGen.GenerateBytes(hkdfOutput, 0, hkdfOutput.Length);

                KeyParameter kek = ParameterUtilities.CreateKeyParameter("AES", hkdfOutput);
                var wrapper = PgpUtilities.CreateWrapper(wrappingAlgo);
                wrapper.Init(false, kek);
                int offset = 0;
                int length = esk.Length;
                if (keyData.Version == PublicKeyEncSessionPacket.Version3)
                {
                    offset = 1;
                    length--;
                }
                var keyBytes = wrapper.Unwrap(esk, offset, length);
                return keyBytes;
            }

            if (keyData.Algorithm != PublicKeyAlgorithmTag.ECDH)
            {
                IBufferedCipher cipher = GetKeyCipher(keyData.Algorithm);

                try
                {
                    cipher.Init(false, privKey.Key);
                }
                catch (InvalidKeyException e)
                {
                    throw new PgpException("error setting asymmetric cipher", e);
                }

                if (keyData.Algorithm == PublicKeyAlgorithmTag.RsaEncrypt
                    || keyData.Algorithm == PublicKeyAlgorithmTag.RsaGeneral)
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

            int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
            if ((2 + pLen + 1) > enc.Length) 
                throw new PgpException("encoded length out of range");

            byte[] pEnc = new byte[pLen];
            Array.Copy(enc, 2, pEnc, 0, pLen);

            int keyLen = enc[pLen + 2];
            if ((2 + pLen + 1 + keyLen) > enc.Length)
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

            IWrapper w = PgpUtilities.CreateWrapper(ecPubKey.SymmetricKeyAlgorithm);
            w.Init(false, key);

            return PgpPad.UnpadSessionData(w.Unwrap(keyEnc, 0, keyEnc.Length));
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
