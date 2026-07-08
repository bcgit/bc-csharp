using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

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

        public SymmetricKeyAlgorithmTag Algorithm => m_keyData.EncAlgorithm;

        public int Version => m_keyData.Version;

        public byte VersionByte => m_keyData.VersionByte;

        /// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public Stream GetDataStream(char[] passPhrase)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            return ImplGetDataStream(rawPassPhrase, clearPassPhrase: true);
        }

        /// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8.
        /// </remarks>
        public Stream GetDataStreamUtf8(char[] passPhrase)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            return ImplGetDataStream(rawPassPhrase, clearPassPhrase: true);
        }

        /// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public Stream GetDataStreamRaw(byte[] rawPassPhrase) =>
            ImplGetDataStream(rawPassPhrase, clearPassPhrase: false);

        internal Stream ImplGetDataStream(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            try
            {
                SymmetricKeyAlgorithmTag keyAlgorithm = m_keyData.EncAlgorithm;

                KeyParameter key = PgpUtilities.DoMakeKeyFromPassPhrase(keyAlgorithm, m_keyData.S2k, rawPassPhrase,
                    clearPassPhrase);

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

                string cipherName = PgpUtilities.GetSymmetricCipherName(keyAlgorithm);
                IBufferedCipher cipher = CreateBufferedCipher(cipherName);
                cipher.Init(forEncryption: false, new ParametersWithIV(key, iv: new byte[cipher.GetBlockSize()]));

                var decStream = InitDecStream(new CipherStream(GetInputStream(), cipher, null));

                byte[] prefix = StreamUtilities.RequireBytes(decStream, cipher.GetBlockSize() + 2);

                /*
                 * The oracle attack on the "quick check" bytes is not deemed a security risk for PBE.
                 */
                QuickCheck(prefix);

                return decStream;
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

        /// <exception cref="PgpException" />
        private KeyParameter GetSessionKey(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            //byte[] key = dataDecryptorFactory.makeKeyFromPassPhrase(keyData.getEncAlgorithm(), keyData.getS2K());
            KeyParameter key = PgpUtilities.DoMakeKeyFromPassPhrase(m_keyData.EncAlgorithm, m_keyData.S2k, rawPassPhrase,
                clearPassPhrase);

            throw new NotImplementedException();

            //int version = Version;
            //switch (version)
            //{
            //case SymmetricKeyEncSessionPacket.Version4:
            //{
            //    byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getEncAlgorithm(), key, keyData.getSecKeyData());
            //    int sessionKeyAlg = sessionData[0] & 0xff;
            //    byte[] sessionKey = Arrays.copyOfRange(sessionData, 1, sessionData.length);
            //    return new PGPSessionKey(sessionKeyAlg, sessionKey);
            //}
            //case SymmetricKeyEncSessionPacket.Version5:
            //case SymmetricKeyEncSessionPacket.Version6:
            //{
            //    int sessionKeyAlg = getSymmetricAlgorithm(dataDecryptorFactory);
            //    byte[] sessionKey = dataDecryptorFactory.recoverAEADEncryptedSessionData(keyData, key);
            //    return new PGPSessionKey(sessionKeyAlg, sessionKey);
            //}
            //default:
            //    throw new UnsupportedPacketVersionException("Unsupported packet version: " + version);
            //}
        }
    }
}
