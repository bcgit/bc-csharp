using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A password based encryption object.</remarks>
    public class PgpPbeEncryptedData
        : PgpEncryptedData
    {
        private readonly SymmetricKeyEncSessionPacket m_keyData;

        internal PgpPbeEncryptedData(SymmetricKeyEncSessionPacket keyData, InputStreamPacket encData)
            : base(encData)
        {
            m_keyData = keyData;
        }

        /// <summary>Return the raw input stream for the data stream.</summary>
        public override Stream GetInputStream() => encData.GetInputStream();

        /// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public Stream GetDataStream(char[] passPhrase)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            return DoGetDataStream(rawPassPhrase, clearPassPhrase: true);
        }

        /// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public Stream GetDataStreamUtf8(char[] passPhrase)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            return DoGetDataStream(rawPassPhrase, clearPassPhrase: true);
        }

        /// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public Stream GetDataStreamRaw(byte[] rawPassPhrase) => DoGetDataStream(rawPassPhrase, clearPassPhrase: false);

        internal Stream DoGetDataStream(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            try
            {
                SymmetricKeyAlgorithmTag keyAlgorithm = m_keyData.EncAlgorithm;

                KeyParameter key = PgpUtilities.DoMakeKeyFromPassPhrase(
                    keyAlgorithm, m_keyData.S2k, rawPassPhrase, clearPassPhrase);

                byte[] secKeyData = m_keyData.GetSecKeyData();
                if (secKeyData != null && secKeyData.Length > 0)
                {
                    IBufferedCipher keyCipher = CipherUtilities.GetCipher(
                        PgpUtilities.GetSymmetricCipherName(keyAlgorithm) + "/CFB/NoPadding");

                    keyCipher.Init(forEncryption: false, new ParametersWithIV(key, new byte[keyCipher.GetBlockSize()]));

                    byte[] keyBytes = keyCipher.DoFinal(secKeyData);

                    keyAlgorithm = (SymmetricKeyAlgorithmTag)keyBytes[0];

                    key = ParameterUtilities.CreateKeyParameter(
                        PgpUtilities.GetSymmetricCipherName(keyAlgorithm),
                        keyBytes, 1, keyBytes.Length - 1);
                }


                IBufferedCipher c = CreateStreamCipher(keyAlgorithm);

                byte[] iv = new byte[c.GetBlockSize()];

                c.Init(forEncryption: false, new ParametersWithIV(key, iv));

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

                bool repeatCheckPassed = iv[iv.Length - 2] == (byte)v1 && iv[iv.Length - 1] == (byte)v2;

                // Note: some versions of PGP appear to produce 0 for the extra
                // bytes rather than repeating the two previous bytes
                bool zerosCheckPassed = v1 == 0 && v2 == 0;

                if (!repeatCheckPassed && !zerosCheckPassed)
                    throw new PgpDataValidationException("quick check failed.");

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

        private IBufferedCipher CreateStreamCipher(SymmetricKeyAlgorithmTag keyAlgorithm)
        {
            string mode = (encData is SymmetricEncIntegrityPacket)
                ? "CFB"
                : "OpenPGPCFB";

            string cName = PgpUtilities.GetSymmetricCipherName(keyAlgorithm) + "/" + mode + "/NoPadding";

            return CipherUtilities.GetCipher(cName);
        }
    }
}
