using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
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

        private byte[] m_V;
        private byte[] m_IV;

        /// <summary>
        /// Set up for use with stream mode, where the key derivation function is used to provide a stream of bytes to
        /// xor with the message.
        /// </summary>
        /// <remarks>
        /// <b>Security note:</b> when this engine is initialised with static keys on both sides (the
        /// <see cref="Init(bool, ICipherParameters, ICipherParameters, ICipherParameters)"/> entry point, which
        /// supplies no ephemeral component) the key-derivation input is the same for every message, so the
        /// stream-mode keystream is identical from message to message - encrypting more than one message under a given
        /// key pair is a many-time pad and leaks plaintext relationships. Use the ephemeral sender-key initialisation
        /// (the standard ECIES mode) for messages that must remain confidential; the static-static mode is effectively
        /// deterministic encryption.
        /// </remarks>
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
            m_V = Array.Empty<byte>();

            ExtractParams(iesParameters);
        }

        private void ExtractParams(ICipherParameters parameters)
        {
            if (parameters is ParametersWithIV withIV)
            {
                m_IV = withIV.GetIV();
                m_parameters = (IesParameters)withIV.Parameters;
            }
            else
            {
                m_IV = null;
                m_parameters = (IesParameters)parameters;
            }
        }

        private byte[] DecryptBlock(byte[] in_enc, int inOff, int inLen)
        {
            byte[] M, K, K1, K2;
            int len = 0;
            int macKeySize = m_parameters.MacKeySize;

            // Ensure that the length of the input is greater than the MAC in bytes
            if (inLen < m_V.Length + m_mac.GetMacSize())
                throw new InvalidCipherTextException("Length of input must be greater than the MAC and V combined");

            // note order is important: set up keys, do simple encryptions, check mac, do final encryption.
            if (m_cipher == null)
            {
                // Streaming mode.
                K1 = new byte[inLen - m_V.Length - m_mac.GetMacSize()];
                K2 = new byte[macKeySize / 8];
                K = new byte[K1.Length + K2.Length];

                m_kdf.GenerateBytes(K, 0, K.Length);

                // K2 (MAC key) from a fixed prefix, K1 (keystream) from the remainder - see encryptBlock.
                Array.Copy(K, 0, K2, 0, K2.Length);
                Array.Copy(K, K2.Length, K1, 0, K1.Length);

                // process the message
                M = new byte[K1.Length];
                Bytes.Xor(K1.Length, in_enc, inOff + m_V.Length, K1, 0, M, 0);
            }
            else
            {
                // Block cipher mode.
                K1 = new byte[((IesWithCipherParameters)m_parameters).CipherKeySize / 8];
                K2 = new byte[macKeySize / 8];
                K = new byte[K1.Length + K2.Length];

                m_kdf.GenerateBytes(K, 0, K.Length);
                Array.Copy(K, 0, K1, 0, K1.Length);
                Array.Copy(K, K1.Length, K2, 0, K2.Length);

                ICipherParameters cp = new KeyParameter(K1);

                // If IV provided use it to initialize the cipher
                if (m_IV != null)
                {
                    cp = new ParametersWithIV(cp, m_IV);
                }

                m_cipher.Init(false, cp);

                M = new byte[m_cipher.GetOutputSize(inLen - m_V.Length - m_mac.GetMacSize())];

                // do initial processing
                len = m_cipher.ProcessBytes(in_enc, inOff + m_V.Length, inLen - m_V.Length - m_mac.GetMacSize(), M, 0);
            }

            // Convert the length of the encoding vector into a byte array.
            byte[] P2 = m_parameters.GetEncodingV();
            byte[] L2 = null;
            if (m_V.Length != 0)
            {
                L2 = GetLengthTag(P2);
            }

            // Verify the MAC.
            int end = inOff + inLen;
            byte[] T1 = Arrays.CopyOfRange(in_enc, end - m_mac.GetMacSize(), end);

            byte[] T2 = new byte[T1.Length];
            m_mac.Init(new KeyParameter(K2));
            m_mac.BlockUpdate(in_enc, inOff + m_V.Length, inLen - m_V.Length - T2.Length);

            if (P2 != null)
            {
                m_mac.BlockUpdate(P2, 0, P2.Length);
            }
            if (m_V.Length != 0)
            {
                m_mac.BlockUpdate(L2, 0, L2.Length);
            }
            m_mac.DoFinal(T2, 0);

            if (!Arrays.FixedTimeEquals(T1, T2))
                throw new InvalidCipherTextException("invalid MAC");

            if (m_cipher == null)
                return M;

            len += m_cipher.DoFinal(M, len);

            return Arrays.CopyOfRange(M, 0, len);
        }

        private byte[] EncryptBlock(byte[] input, int inOff, int inLen)
        {
            byte[] C, K, K1, K2;
            int len;
            int macKeySize = m_parameters.MacKeySize;

            if (m_cipher == null)
            {
                // Streaming mode.
                K1 = new byte[inLen];
                K2 = new byte[macKeySize / 8];
                K = new byte[K1.Length + K2.Length];

                m_kdf.GenerateBytes(K, 0, K.Length);

                // Derive the MAC key K2 from a fixed prefix of the KDF output and the keystream K1 from
                // the remainder, regardless of whether an ephemeral V is present. Placing K1 first (the
                // legacy static-key, V-absent layout) put K2 at a message-length-dependent offset behind
                // the keystream, so a single known-plaintext leak of K1 also exposed the MAC key of any
                // shorter message - a cross-message forgery in the deterministic static-key mode. A fixed
                // K2 offset is never covered by the keystream, closing that.
                Array.Copy(K, 0, K2, 0, K2.Length);
                Array.Copy(K, K2.Length, K1, 0, K1.Length);

                C = new byte[inLen];
                Bytes.Xor(inLen, input, inOff, K1, 0, C, 0);
                len = inLen;
            }
            else
            {
                K1 = new byte[((IesWithCipherParameters)m_parameters).CipherKeySize / 8];
                K2 = new byte[macKeySize / 8];
                K = new byte[K1.Length + K2.Length];

                m_kdf.GenerateBytes(K, 0, K.Length);
                Array.Copy(K, 0, K1, 0, K1.Length);
                Array.Copy(K, K1.Length, K2, 0, K2.Length);

                ICipherParameters cp = new KeyParameter(K1);

                // If IV provide use it to initialize the cipher
                if (m_IV != null)
                {
                    cp = new ParametersWithIV(cp, m_IV);
                }

                m_cipher.Init(true, cp);

                C = new byte[m_cipher.GetOutputSize(inLen)];
                len = m_cipher.ProcessBytes(input, inOff, inLen, C, 0);
                len += m_cipher.DoFinal(C, len);
            }

            // Convert the length of the encoding vector into a byte array.
            byte[] P2 = m_parameters.GetEncodingV();
            byte[] L2 = null;
            if (m_V.Length != 0)
            {
                L2 = GetLengthTag(P2);
            }

            // Apply the MAC.
            byte[] T = new byte[m_mac.GetMacSize()];

            m_mac.Init(new KeyParameter(K2));
            m_mac.BlockUpdate(C, 0, len);
            if (P2 != null)
            {
                m_mac.BlockUpdate(P2, 0, P2.Length);
            }
            if (m_V.Length != 0)
            {
                m_mac.BlockUpdate(L2, 0, L2.Length);
            }
            m_mac.DoFinal(T, 0);

            // Output the triple (V,C,T).
            byte[] output = new byte[m_V.Length + len + T.Length];
            Array.Copy(m_V, 0, output, 0, m_V.Length);
            Array.Copy(C, 0, output, m_V.Length, len);
            Array.Copy(T, 0, output, m_V.Length + len, T.Length);
            return output;
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
            byte[] Z = BigIntegers.AsUnsignedByteArray(m_agreement.GetFieldSize(), z);

            // Create input to KDF.
            if (m_V.Length > 0)
            {
                byte[] VZ = Arrays.Concatenate(m_V, Z);
                Arrays.ZeroMemory(Z);
                Z = VZ;
            }

            try
            {
                // Initialise the KDF.
                KdfParameters kdfParam = new KdfParameters(Z, m_parameters.GetDerivationV());
                m_kdf.Init(kdfParam);

                return m_forEncryption
                    ? EncryptBlock(input, inOff, inLen)
                    : DecryptBlock(input, inOff, inLen);
            }
            finally
            {
                Arrays.ZeroMemory(Z);
            }
        }

        // as described in Shroup's paper and P1363a
        private static byte[] GetLengthTag(byte[] p2)
        {
            byte[] L2 = new byte[8];
            if (p2 != null)
            {
                Pack.UInt64_To_BE((ulong)(p2.Length * 8L), L2, 0);
            }
            return L2;
        }
    }
}
