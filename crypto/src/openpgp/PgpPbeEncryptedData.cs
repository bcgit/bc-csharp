using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

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

        /// <summary>The symmetric algorithm of the session key packet.</summary>
        /// <remarks>
        /// For version 4 packets this is the algorithm used to encrypt the session key (if any), which is not
        /// necessarily the one that protects the data. See <see cref="GetSymmetricAlgorithm"/>.
        /// </remarks>
        public SymmetricKeyAlgorithmTag Algorithm => m_keyData.EncAlgorithm;

        /// <summary>The symmetric algorithm that protects the data.</summary>
        /// <remarks>
        /// For a version 6 session key packet this is the cipher of the version 2 SEIPD packet. For a version 4
        /// packet it is the algorithm of the session key packet; if the packet has an encrypted session key, the
        /// algorithm of the data is only known once the session key has been recovered.
        /// </remarks>
        public SymmetricKeyAlgorithmTag GetSymmetricAlgorithm()
        {
            if (m_keyData.Version == SymmetricKeyEncSessionPacket.Version6 &&
                EncryptedPacket is SymmetricEncIntegrityPacket seipd &&
                seipd.Version == SymmetricEncIntegrityPacket.Version2)
            {
                return seipd.CipherAlgorithm;
            }

            return m_keyData.EncAlgorithm;
        }

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
            switch (m_keyData.Version)
            {
            case SymmetricKeyEncSessionPacket.Version4:
                return ImplGetV4DataStream(rawPassPhrase, clearPassPhrase);
            case SymmetricKeyEncSessionPacket.Version6:
                return ImplGetV6DataStream(rawPassPhrase, clearPassPhrase);
            default:
                throw new PgpException("unsupported SKESK version: " + m_keyData.Version);
            }
        }

        /// <summary>RFC 9580 5.3.2 and 5.13.2: a version 6 SKESK packet and a version 2 SEIPD packet.</summary>
        private Stream ImplGetV6DataStream(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            if (!(EncryptedPacket is SymmetricEncIntegrityPacket seipd) ||
                seipd.Version != SymmetricEncIntegrityPacket.Version2)
            {
                throw new PgpException("a version 6 SKESK packet requires a version 2 SEIPD packet");
            }

            SymmetricKeyAlgorithmTag keyAlgorithm = m_keyData.EncAlgorithm;
            AeadAlgorithmTag aeadAlgorithm = m_keyData.AeadAlgorithm;
            S2k s2k = m_keyData.S2k;

            // RFC 9580 9.5: these hashes must not be used to derive keys in version 6 packets
            if (s2k.Type != S2k.Argon2 && PgpUtilities.IsWeakS2kHash(s2k.HashAlgorithm))
                throw new PgpDataValidationException("S2K hash algorithm not allowed in version 6 SKESK packets");

            if (!PgpAead.IsSupportedCipher(keyAlgorithm))
                throw new PgpException("unsupported symmetric algorithm in SKESK packet: " + keyAlgorithm);

            byte[] s2kKey = null, kek = null, sessionKey = null;
            try
            {
                s2kKey = PgpUtilities.DoMakeKeyFromPassPhrase(keyAlgorithm, s2k, rawPassPhrase, clearPassPhrase)
                    .GetKey();

                byte[] aad = m_keyData.GetAAData();
                kek = PgpAead.Hkdf(s2kKey, null, aad, SymmetricKeyUtilities.GetKeyLengthInOctets(keyAlgorithm));

                try
                {
                    sessionKey = PgpAead.DecryptOneShot(keyAlgorithm, aeadAlgorithm, kek, m_keyData.GetIV(), aad,
                        Arrays.Concatenate(m_keyData.GetSecKeyData(), m_keyData.GetAuthTag()));
                }
                catch (InvalidCipherTextException e)
                {
                    throw new PgpDataValidationException("passphrase or session key check failed", e);
                }

                // the session key is for the cipher of the SEIPD packet, which can differ from the SKESK cipher
                if (!PgpAead.IsSupportedCipher(seipd.CipherAlgorithm) ||
                    sessionKey.Length != SymmetricKeyUtilities.GetKeyLengthInOctets(seipd.CipherAlgorithm))
                {
                    throw new PgpDataValidationException("passphrase or session key check failed");
                }

                return InitAeadDecStream(sessionKey);
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
                if (sessionKey != null)
                {
                    Arrays.ZeroMemory(sessionKey);
                }
            }
        }

        private Stream ImplGetV4DataStream(byte[] rawPassPhrase, bool clearPassPhrase)
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
    }
}
