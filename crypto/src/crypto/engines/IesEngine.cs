using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>
    /// Support class for constructing intergrated encryption ciphers for doing basic message exchanges on top of key
    /// agreement ciphers.
    /// </summary>
    public class IesEngine
    {
        private readonly IBasicAgreement m_agreement;
        private readonly IDerivationFunction m_kdf;
        private readonly IMac m_mac;
        private readonly BufferedBlockCipher m_cipher;
        private readonly byte[] m_macBuf;

        private bool m_forEncryption;
        private ICipherParameters m_privParam, m_pubParam;
        private IesParameters m_parameters;

        /// <summary>
        /// Set up for use with stream mode, where the key derivation function is used to provide a stream of bytes to
        /// xor with the message.
        /// </summary>
        /// <param name="agree">The key agreement used as the basis for the encryption.</param>
        /// <param name="kdf">The key derivation function used for byte generation.</param>
        /// <param name="mac">The message authentication code generator for the message.</param>
        public IesEngine(IBasicAgreement agree, IDerivationFunction kdf, IMac mac)
        {
            m_agreement = agree;
            m_kdf = kdf;
            m_mac = mac;
            m_cipher = null;
            m_macBuf = new byte[mac.GetMacSize()];
        }

        /// <summary>
        /// Set up for use in conjunction with a block cipher to handle the message.
        /// </summary>
        /// <param name="agree">The key agreement used as the basis for the encryption.</param>
        /// <param name="kdf">The key derivation function used for byte generation.</param>
        /// <param name="mac">The message authentication code generator for the message.</param>
        /// <param name="cipher">The cipher used for encrypting the message</param>
        public IesEngine(IBasicAgreement agree, IDerivationFunction kdf, IMac mac, BufferedBlockCipher cipher)
        {
            m_agreement = agree;
            m_kdf = kdf;
            m_mac = mac;
            m_cipher = cipher;
            m_macBuf = new byte[mac.GetMacSize()];
        }

        /**
        * Initialise the encryptor.
        *
        * @param forEncryption whether or not this is encryption/decryption.
        * @param privParam our private key parameters
        * @param pubParam the recipient's/sender's public key parameters
        * @param param encoding and derivation parameters.
        */
        public virtual void Init(bool forEncryption, ICipherParameters privParameters, ICipherParameters pubParameters,
            ICipherParameters iesParameters)
        {
            m_forEncryption = forEncryption;
            m_privParam = privParameters;
            m_pubParam = pubParameters;
            m_parameters = (IesParameters)iesParameters;
        }

        private byte[] DecryptBlock(byte[] in_enc, int inOff, int inLen, byte[] z)
        {
            byte[] M = null;
            KeyParameter macKey = null;
            KdfParameters kParam = new KdfParameters(z, m_parameters.GetDerivationV());
            int macKeySize = m_parameters.MacKeySize;

            m_kdf.Init(kParam);

            // Ensure that the length of the input is greater than the MAC in bytes
            if (inLen < m_mac.GetMacSize())
                throw new InvalidCipherTextException("Length of input must be greater than the MAC");

            inLen -= m_mac.GetMacSize();

            if (m_cipher == null)     // stream mode
            {
                byte[] Buffer = GenerateKdfBytes(kParam, inLen + (macKeySize / 8));

                M = new byte[inLen];

                for (int i = 0; i != inLen; i++)
                {
                    M[i] = (byte)(in_enc[inOff + i] ^ Buffer[i]);
                }

                macKey = new KeyParameter(Buffer, inLen, (macKeySize / 8));
            }
            else
            {
                int cipherKeySize = ((IesWithCipherParameters)m_parameters).CipherKeySize;
                byte[] Buffer = GenerateKdfBytes(kParam, (cipherKeySize / 8) + (macKeySize / 8));

                m_cipher.Init(false, new KeyParameter(Buffer, 0, (cipherKeySize / 8)));

                M = m_cipher.DoFinal(in_enc, inOff, inLen);

                macKey = new KeyParameter(Buffer, (cipherKeySize / 8), (macKeySize / 8));
            }

            byte[] macIV = m_parameters.GetEncodingV();

            m_mac.Init(macKey);
            m_mac.BlockUpdate(in_enc, inOff, inLen);
            m_mac.BlockUpdate(macIV, 0, macIV.Length);
            m_mac.DoFinal(m_macBuf, 0);

            inOff += inLen;

            byte[] T1 = Arrays.CopyOfRange(in_enc, inOff, inOff + m_macBuf.Length);

            if (!Arrays.FixedTimeEquals(T1, m_macBuf))
                throw new InvalidCipherTextException("Invalid MAC.");

            return M;
        }

        private byte[] EncryptBlock(byte[] input, int inOff, int inLen, byte[] z)
        {
            byte[] C = null;
            KeyParameter macKey = null;
            KdfParameters kParam = new KdfParameters(z, m_parameters.GetDerivationV());
            int c_text_length = 0;
            int macKeySize = m_parameters.MacKeySize;

            if (m_cipher == null)     // stream mode
            {
                byte[] Buffer = GenerateKdfBytes(kParam, inLen + (macKeySize / 8));

                C = new byte[inLen + m_mac.GetMacSize()];
                c_text_length = inLen;

                for (int i = 0; i != inLen; i++)
                {
                    C[i] = (byte)(input[inOff + i] ^ Buffer[i]);
                }

                macKey = new KeyParameter(Buffer, inLen, (macKeySize / 8));
            }
            else
            {
                int cipherKeySize = ((IesWithCipherParameters)m_parameters).CipherKeySize;
                byte[] Buffer = GenerateKdfBytes(kParam, (cipherKeySize / 8) + (macKeySize / 8));

                m_cipher.Init(true, new KeyParameter(Buffer, 0, (cipherKeySize / 8)));

                c_text_length = m_cipher.GetOutputSize(inLen);
                byte[] tmp = new byte[c_text_length];

                int len = m_cipher.ProcessBytes(input, inOff, inLen, tmp, 0);
                len += m_cipher.DoFinal(tmp, len);

                C = new byte[len + m_mac.GetMacSize()];
                c_text_length = len;

                Array.Copy(tmp, 0, C, 0, len);

                macKey = new KeyParameter(Buffer, (cipherKeySize / 8), (macKeySize / 8));
            }

            byte[] macIV = m_parameters.GetEncodingV();

            m_mac.Init(macKey);
            m_mac.BlockUpdate(C, 0, c_text_length);
            m_mac.BlockUpdate(macIV, 0, macIV.Length);
            m_mac.DoFinal(C, c_text_length);
            return C;
        }

        private byte[] GenerateKdfBytes(KdfParameters kParam, int length)
        {
            byte[] buf = new byte[length];
            m_kdf.Init(kParam);
            m_kdf.GenerateBytes(buf, 0, buf.Length);
            return buf;
        }

        public virtual byte[] ProcessBlock(byte[] input, int inOff, int inLen)
        {
            m_agreement.Init(m_privParam);

            BigInteger z = m_agreement.CalculateAgreement(m_pubParam);

            byte[] zBytes = BigIntegers.AsUnsignedByteArray(m_agreement.GetFieldSize(), z);

            try
            {
                return m_forEncryption
                    ? EncryptBlock(input, inOff, inLen, zBytes)
                    : DecryptBlock(input, inOff, inLen, zBytes);
            }
            finally
            {
                Array.Clear(zBytes, 0, zBytes.Length);
            }
        }
    }
}
