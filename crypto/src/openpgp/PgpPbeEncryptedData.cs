using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A password based encryption object.</remarks>
    public class PgpPbeEncryptedData
        : PgpEncryptedData
    {
        private readonly SymmetricKeyEncSessionPacket keyData;

		internal PgpPbeEncryptedData(
			SymmetricKeyEncSessionPacket	keyData,
			InputStreamPacket				encData)
			: base(encData)
		{
			this.keyData = keyData;
            EnforceConstraints();
        }

        private void EnforceConstraints()
        {
            switch (keyData.Version)
            {
                case SymmetricKeyEncSessionPacket.Version4:
                    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-4-symmetric-key-enc
                    // A version 4 SKESK packet precedes a version 1 SEIPD packet. In historic data, it is sometimes found
                    // preceding a deprecated SED packet. A v4 SKESK packet MUST NOT precede a v2 SEIPD packet.
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

                        // V2 SEIPD cannot be preceded by V4 SKESK
                        throw new PgpException($"Version 4 SKESK cannot precede SEIPD of version {seipd1.Version}");
                    }
                    break;

                case SymmetricKeyEncSessionPacket.Version5:
                    // https://www.ietf.org/archive/id/draft-koch-openpgp-2015-rfc4880bis-01.html does not state any constraints
                    break;

                case SymmetricKeyEncSessionPacket.Version6:
                    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-6-symmetric-key-enc
                    // A version 6 SKESK packet precedes a version 2 SEIPD packet. A v6 SKESK packet MUST NOT precede a v1 SEIPD
                    // packet or a deprecated Symmetrically Encrypted Data.
                    if (encData is SymmetricEncDataPacket)
                    {
                        throw new PgpException("Version 6 SKESK MUST NOT precede a deprecated SED packet.");
                    }

                    if (encData is SymmetricEncIntegrityPacket seipd2)
                    {
                        if (seipd2.Version == SymmetricEncIntegrityPacket.Version2)
                        {
                            return;
                        }
                        throw new PgpException($"Version 6 PKESK cannot precede SEIPD of version {seipd2.Version}");
                    }
                    break;
                default:
                    throw new UnsupportedPacketVersionException($"Unsupported PGP secret key encrypted session key packet version encountered: {keyData.Version}");
            }
        }

        /// <summary>Return the raw input stream for the data stream.</summary>
        public override Stream GetInputStream()
		{
			return encData.GetInputStream();
		}

		/// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public Stream GetDataStream(char[] passPhrase)
        {
            return DoGetDataStream(PgpUtilities.EncodePassPhrase(passPhrase, false), true);
        }

		/// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public Stream GetDataStreamUtf8(char[] passPhrase)
        {
            return DoGetDataStream(PgpUtilities.EncodePassPhrase(passPhrase, true), true);
        }

		/// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public Stream GetDataStreamRaw(byte[] rawPassPhrase)
        {
            return DoGetDataStream(rawPassPhrase, false);
        }

        private Stream DoGetDataStreamVersion1(byte[] rawPassPhrase, bool clearPassPhrase)
        {
			try
			{
				SymmetricKeyAlgorithmTag keyAlgorithm = keyData.EncAlgorithm;

				KeyParameter key = PgpUtilities.DoMakeKeyFromPassPhrase(
					keyAlgorithm, keyData.S2k, rawPassPhrase, clearPassPhrase);

                byte[] secKeyData = keyData.GetSecKeyData();
				if (secKeyData != null && secKeyData.Length > 0)
				{
					IBufferedCipher keyCipher = CipherUtilities.GetCipher(
						PgpUtilities.GetSymmetricCipherName(keyAlgorithm) + "/CFB/NoPadding");

					keyCipher.Init(false,
						new ParametersWithIV(key, new byte[keyCipher.GetBlockSize()]));

					byte[] keyBytes = keyCipher.DoFinal(secKeyData);

					keyAlgorithm = (SymmetricKeyAlgorithmTag) keyBytes[0];

					key = ParameterUtilities.CreateKeyParameter(
						PgpUtilities.GetSymmetricCipherName(keyAlgorithm),
						keyBytes, 1, keyBytes.Length - 1);
				}


				IBufferedCipher c = CreateStreamCipher(keyAlgorithm);

				byte[] iv = new byte[c.GetBlockSize()];

				c.Init(false, new ParametersWithIV(key, iv));

				encStream = BcpgInputStream.Wrap(new CipherStream(encData.GetInputStream(), c, null));

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


				// Note: the oracle attack on the "quick check" bytes is not deemed
				// a security risk for PBE (see PgpPublicKeyEncryptedData)

				bool repeatCheckPassed =
						iv[iv.Length - 2] == (byte)v1
					&&	iv[iv.Length - 1] == (byte)v2;

				// Note: some versions of PGP appear to produce 0 for the extra
				// bytes rather than repeating the two previous bytes
				bool zeroesCheckPassed =
						v1 == 0
					&&	v2 == 0;

				if (!repeatCheckPassed && !zeroesCheckPassed)
				{
					throw new PgpDataValidationException("quick check failed.");
				}

				return encStream;
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

        private static KeyParameter DeriveVersion6SessionKey(SymmetricKeyEncSessionPacket keyData, byte[] rawPassPhrase, bool clearPassPhrase)
        {
            var keyAlgorithm = keyData.EncAlgorithm;
            var aeadAlgo = keyData.AeadAlgorithm;
            var aeadIV = keyData.GetAeadIV();
            var hkdfInfo = keyData.GetAAData();
            var secKeyData = keyData.GetSecKeyData();

            var keyAlgoName = PgpUtilities.GetSymmetricCipherName(keyAlgorithm);
            var aeadAlgoName = AeadUtils.GetAeadAlgorithmName(aeadAlgo);
            var keyCipher = CipherUtilities.GetCipher($"{keyAlgoName}/{aeadAlgoName}/NoPadding");

            var key = PgpUtilities.DoMakeKeyFromPassPhrase(keyAlgorithm, keyData.S2k, rawPassPhrase, clearPassPhrase);

            var hkdfParams = new HkdfParameters(key.GetKey(), Array.Empty<byte>(), hkdfInfo);
            var hkdfGen = new HkdfBytesGenerator(PgpUtilities.CreateDigest(HashAlgorithmTag.Sha256));
            hkdfGen.Init(hkdfParams);
            var hkdfOutput = new byte[PgpUtilities.GetKeySizeInOctets(keyAlgorithm)];
            hkdfGen.GenerateBytes(hkdfOutput, 0, hkdfOutput.Length);

            var aeadParams = new AeadParameters(
                new KeyParameter(hkdfOutput),
                8 * AeadUtils.GetAuthTagLength(aeadAlgo),
                aeadIV,
                hkdfInfo);

            keyCipher.Init(false, aeadParams);
            byte[] keyBytes = keyCipher.DoFinal(secKeyData);

            return ParameterUtilities.CreateKeyParameter(
                PgpUtilities.GetSymmetricCipherName(keyAlgorithm),
                keyBytes, 0, keyBytes.Length);
        }

        private Stream DoGetDataStreamVersion2(SymmetricEncIntegrityPacket seipd, byte[] rawPassPhrase, bool clearPassPhrase)
        {
            try
            {
                KeyParameter sessionKey = DeriveVersion6SessionKey(keyData, rawPassPhrase, clearPassPhrase);

                var aadata = seipd.GetAAData();
                var salt = seipd.GetSalt();
                AeadUtils.DeriveAeadMessageKeyAndIv(sessionKey, seipd.CipherAlgorithm, seipd.AeadAlgorithm, salt, aadata, out var messageKey, out var iv);
                var cipher = AeadUtils.CreateAeadCipher(seipd.CipherAlgorithm, seipd.AeadAlgorithm);

                var aeadStream = new AeadInputStream(
                    encData.GetInputStream(),
                    cipher,
                    messageKey,
                    iv,
                    seipd.AeadAlgorithm,
                    seipd.ChunkSize,
                    aadata);

                encStream = BcpgInputStream.Wrap(aeadStream);
                return encStream;
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
        
        internal Stream DoGetDataStream(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            if (encData is SymmetricEncIntegrityPacket seipd && seipd.Version == SymmetricEncIntegrityPacket.Version2)
            {
                return DoGetDataStreamVersion2(seipd, rawPassPhrase, clearPassPhrase);
            }
            else
            {
                return DoGetDataStreamVersion1(rawPassPhrase, clearPassPhrase);
            }
        }

        private IBufferedCipher CreateStreamCipher(
			SymmetricKeyAlgorithmTag keyAlgorithm)
		{
			string mode = (encData is SymmetricEncIntegrityPacket)
				? "CFB"
				: "OpenPGPCFB";

			string cName = $"{PgpUtilities.GetSymmetricCipherName(keyAlgorithm)}/{mode}/NoPadding";

			return CipherUtilities.GetCipher(cName);
		}

    }
}
