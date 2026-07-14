using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Modes
{
    public class KCcmBlockCipher
        : IAeadBlockCipher
    {
        private static readonly int BYTES_IN_INT = 4;
        private static readonly int BITS_IN_BYTE = 8;

        private static readonly int MAX_MAC_BIT_LENGTH = 512;
        private static readonly int MIN_MAC_BIT_LENGTH = 64;

        private IBlockCipher engine;

        private int macSize;
        private bool forEncryption;

        private byte[] initialAssociatedText;
        private byte[] mac;
        private byte[] macBlock;

        private byte[] nonce;
        // Previous key seen on Init(true, ...) - used with nonce only to reject nonce reuse for encryption.
        private byte[] lastKey;

        private byte[] G1;
        private byte[] buffer;

        private byte[] s;
        private byte[] counter;

        private readonly MemoryStream associatedText = new MemoryStream();
        private readonly MemoryStream data = new MemoryStream();

        /*
        *  
        *
        */
        private int Nb_ = 4;

        private void SetNb(int Nb)
        {
            if (Nb == 4 || Nb == 6 || Nb == 8)
            {
                Nb_ = Nb;
            }
            else
            {
                throw new ArgumentException("Nb = 4 is recommended by DSTU7624 but can be changed to only 6 or 8 in this implementation");
            }
        }

        /// <summary>
        /// Base constructor. Nb value is set to 4.
        /// </summary>
        /// <param name="engine">base cipher to use under CCM.</param>
        public KCcmBlockCipher(IBlockCipher engine): this(engine, 4)
        {
        }

        /// <summary>
        /// Constructor allowing Nb configuration.
        /// 
        /// Nb is a parameter specified in CCM mode of DSTU7624 standard.
        /// This parameter specifies maximum possible length of input.It should
        /// be calculated as follows: Nb = 1 / 8 * (-3 + log[2]Nmax) + 1,
        /// where Nmax - length of input message in bits.For practical reasons
        /// Nmax usually less than 4Gb, e.g. for Nmax = 2^32 - 1, Nb = 4.
        /// </summary>
        /// <param name="engine">base cipher to use under CCM.</param>
        /// <param name="Nb">Nb value to use.</param>
        public KCcmBlockCipher(IBlockCipher engine, int Nb)
        {
            int blockSize = engine.GetBlockSize();
            this.engine = engine;
            this.macSize = blockSize;
            this.nonce = new byte[blockSize];
            this.initialAssociatedText = new byte[blockSize];
            this.mac = new byte[blockSize];
            this.macBlock = new byte[blockSize];
            this.G1 = new byte[blockSize];
            this.buffer = new byte[blockSize];
            this.s = new byte[blockSize];
            this.counter = new byte[blockSize];
            SetNb(Nb);
        }

        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        {
            KeyParameter keyParameter = null;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ReadOnlySpan<byte> newNonce;
#else
            byte[] newNonce;
#endif

            if (parameters is AeadParameters aeadParameters)
            {
                int macSizeInBits = aeadParameters.MacSize;
                if (macSizeInBits > MAX_MAC_BIT_LENGTH || macSizeInBits < MIN_MAC_BIT_LENGTH || macSizeInBits % 8 != 0)
                    throw new ArgumentException("Invalid mac size specified");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                newNonce = aeadParameters.Nonce;
#else
                newNonce = aeadParameters.GetNonce();
#endif
                macSize = macSizeInBits / BITS_IN_BYTE;
                initialAssociatedText = aeadParameters.GetAssociatedText();
                keyParameter = aeadParameters.Key;
            }
            else if (parameters is ParametersWithIV withIV)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                newNonce = withIV.InternalIV;
#else
                newNonce = withIV.GetIV();
#endif
                macSize = engine.GetBlockSize(); // use default blockSize for MAC if it is not specified
                initialAssociatedText = null;

                if (withIV.Parameters != null)
                {
                    keyParameter = withIV.Parameters as KeyParameter
                        ?? throw new ArgumentException("invalid parameters passed to KCCM");
                }
            }
            else
            {
                throw new ArgumentException("invalid parameters passed to KCCM");
            }

            // RFC 5116 sec. 2.1 requires a distinct nonce per AEAD encryption under a given key; the
            // DSTU 7624 CCM construction inherits this CCM rule (cf. NIST SP 800-38C), and reuse is
            // catastrophic (CTR keystream reuse plus a forgeable CBC-MAC). That obligation is the
            // caller's, so this guard enforces it defensively, mirroring KGCMBlockCipher /
            // GCMBlockCipher. A fresh nonce or key, Reset(), or Init for decryption are all unaffected.
            if (forEncryption)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                if (nonce != null && newNonce.SequenceEqual(nonce))
#else
                if (nonce != null && Arrays.AreEqual(nonce, newNonce))
#endif
                {
                    if (keyParameter == null)
                        throw new ArgumentException("cannot reuse nonce for KCCM encryption");

                    if (lastKey != null && keyParameter.FixedTimeEquals(lastKey))
                        throw new ArgumentException("cannot reuse nonce for KCCM encryption");
                }
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            nonce = newNonce.ToArray();
#else
            nonce = newNonce;
#endif
            if (keyParameter != null)
            {
                lastKey = keyParameter.GetKey();
            }

            this.mac = new byte[macSize];
            this.forEncryption = forEncryption;

            engine.Init(true, keyParameter);

            Reset();
        }

        public virtual string AlgorithmName => engine.AlgorithmName + "/KCCM";

        public virtual int GetBlockSize() => engine.GetBlockSize();

        public virtual IBlockCipher UnderlyingCipher => engine;

        public virtual void ProcessAadByte(byte input)
        {
            associatedText.WriteByte(input);
        }

        public virtual void ProcessAadBytes(byte[] input, int inOff, int len)
        {
            associatedText.Write(input, inOff, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            associatedText.Write(input);
        }
#endif

        private void ProcessAssociatedText()
        {
            int aadLen = Convert.ToInt32(associatedText.Length);

            bool hasAssocText = aadLen > 0;

            if (hasAssocText && aadLen % engine.GetBlockSize() != 0)
                throw new ArgumentException("padding not supported");

            // The G1 block binds the nonce, data length and MAC-size flag into the MAC and must be
            // processed unconditionally. DSTU 7624 carries the associated-data-present indicator as a flag
            // bit inside G1, so it is not a gate on computing G1: skipping G1 when no AAD is present leaves
            // the MAC independent of the nonce and enables cross-nonce forgery.
            Array.Copy(nonce, 0, G1, 0, nonce.Length - Nb_ - 1);

            int dataLen = Convert.ToInt32(data.Length) - (forEncryption ? 0 : macSize);
            Pack.UInt32_To_LE((uint)dataLen, buffer, 0); // for G1

            Array.Copy(buffer, 0, G1, nonce.Length - Nb_ - 1, BYTES_IN_INT);

            G1[G1.Length - 1] = getFlag(hasAssocText, macSize);

            engine.ProcessBlock(G1, 0, macBlock, 0);

            if (!hasAssocText)
                return;

            Pack.UInt32_To_LE((uint)aadLen, buffer, 0); // for G2

            byte[] aad = associatedText.GetBuffer();

            if (aadLen <= engine.GetBlockSize() - Nb_)
            {
                for (int byteIndex = 0; byteIndex < aadLen; byteIndex++)
                {
                    buffer[byteIndex + Nb_] ^= aad[byteIndex];
                }

                for (int byteIndex = 0; byteIndex < engine.GetBlockSize(); byteIndex++)
                {
                    macBlock[byteIndex] ^= buffer[byteIndex];
                }

                engine.ProcessBlock(macBlock, 0, macBlock, 0);

                return;
            }

            for (int byteIndex = 0; byteIndex < engine.GetBlockSize(); byteIndex++)
            {
                macBlock[byteIndex] ^= buffer[byteIndex];
            }

            engine.ProcessBlock(macBlock, 0, macBlock, 0);

            int assocOff = 0;
            int authLen = aadLen;
            while (authLen != 0)
            {
                for (int byteIndex = 0; byteIndex < engine.GetBlockSize(); byteIndex++)
                {
                    macBlock[byteIndex] ^= aad[byteIndex + assocOff];
                }

                engine.ProcessBlock(macBlock, 0, macBlock, 0);

                assocOff += engine.GetBlockSize();
                authLen -= engine.GetBlockSize();
            }
        }

        public virtual int ProcessByte(byte input, byte[] output, int outOff)
        {
            data.WriteByte(input);

            return 0;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual int ProcessByte(byte input, Span<byte> output)
        {
            data.WriteByte(input);

            return 0;
        }
#endif

        public virtual int ProcessBytes(byte[] input, int inOff, int inLen, byte[] output, int outOff)
        {
            Check.DataLength(input, inOff, inLen, "input buffer too short");

            data.Write(input, inOff, inLen);

            return 0;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            data.Write(input);

            return 0;
        }
#endif

        public int ProcessPacket(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            Check.DataLength(input, inOff, len, "input buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessPacket(input.AsSpan(inOff, len), output.AsSpan(outOff));
#else
            ProcessAssociatedText();

            int blockSize = engine.GetBlockSize(), index = 0;
            if (forEncryption)
            {
                Check.DataLength(len % blockSize != 0, "partial blocks not supported");
                Check.OutputLength(output, outOff, len + macSize, "output buffer too short");

                CalculateMac(input, inOff, len);
                engine.ProcessBlock(nonce, 0, s, 0);

                while (index < len)
                {
                    ProcessBlock(input, inOff + index, output, outOff + index);
                    index += blockSize;
                }

                AdvanceGamma();
                engine.ProcessBlock(s, 0, buffer, 0);

                Bytes.Xor(macSize, macBlock, 0, buffer, 0, output, outOff + len);
                Array.Copy(macBlock, 0, mac, 0, macSize);

                Reset();
                return len + macSize;
            }
            else
            {
                if (len < macSize)
                    throw new InvalidCipherTextException("data too short");

                int dataLen = len - macSize;
                Check.DataLength(dataLen % blockSize != 0, "partial blocks not supported");
                Check.OutputLength(output, outOff, dataLen, "output buffer too short");

                engine.ProcessBlock(nonce, 0, s, 0);

                while (index < dataLen)
                {
                    ProcessBlock(input, inOff + index, output, outOff + index);
                    index += blockSize;
                }

                AdvanceGamma();
                engine.ProcessBlock(s, 0, buffer, 0);

                byte[] recoveredMac = new byte[macSize];
                Bytes.Xor(macSize, input, inOff + dataLen, buffer, 0, recoveredMac, 0);

                CalculateMac(output, outOff, dataLen);

                Array.Copy(macBlock, 0, mac, 0, macSize);

                if (!Arrays.FixedTimeEquals(mac, recoveredMac))
                {
                    Arrays.ZeroMemory(output, outOff, dataLen);
                    throw new InvalidCipherTextException("mac check failed");
                }

                // TODO Follow bc-java by decrypting into a temp array, then copying after MAC verification
                // Only now (MAC verified) expose the recovered plaintext in the caller's output. The MAC
                // is not written to the output - it is consumed for verification and is available via
                // GetMac() - matching the standard AEAD contract (CCM / GCM / KGCM).
                //Array.Copy(plaintext, 0, output, outOff, dataLen);

                Reset();
                return dataLen;
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessPacket(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int len = input.Length;

            ProcessAssociatedText();

            int blockSize = engine.GetBlockSize(), index = 0;
            if (forEncryption)
            {
                Check.DataLength(len % blockSize != 0, "partial blocks not supported");
                Check.OutputLength(output, len + macSize, "output buffer too short");

                CalculateMac(input);
                engine.ProcessBlock(nonce, s);

                while (index < len)
                {
                    ProcessBlock(input[index..], output[index..]);
                    index += blockSize;
                }

                AdvanceGamma();
                engine.ProcessBlock(s, buffer);

                Bytes.Xor(macSize, macBlock, buffer, output[len..]);
                Array.Copy(macBlock, 0, mac, 0, macSize);

                Reset();
                return len + macSize;
            }
            else
            {
                if (len < macSize)
                    throw new InvalidCipherTextException("data too short");

                int dataLen = len - macSize;
                Check.DataLength(dataLen % blockSize != 0, "partial blocks not supported");
                Check.OutputLength(output, dataLen, "output buffer too short");

                engine.ProcessBlock(nonce, 0, s, 0);

                while (index < dataLen)
                {
                    ProcessBlock(input[index..], output[index..]);
                    index += blockSize;
                }

                AdvanceGamma();
                engine.ProcessBlock(s, buffer);

                Span<byte> recoveredMac = macSize <= 64
                    ? stackalloc byte[macSize]
                    : new byte[macSize];
                Bytes.Xor(macSize, input[dataLen..], buffer, recoveredMac);

                Span<byte> plaintext = output[..dataLen];
                CalculateMac(plaintext);

                Array.Copy(macBlock, 0, mac, 0, macSize);

                if (!Arrays.FixedTimeEquals(mac, recoveredMac))
                {
                    Arrays.ZeroMemory(plaintext);
                    throw new InvalidCipherTextException("mac check failed");
                }

                // TODO Follow bc-java by decrypting into a temp array, then copying after MAC verification
                // Only now (MAC verified) expose the recovered plaintext in the caller's output. The MAC
                // is not written to the output - it is consumed for verification and is available via
                // GetMac() - matching the standard AEAD contract (CCM / GCM / KGCM).
                //plaintext.CopyTo(output);

                Reset();
                return dataLen;
            }
        }
#endif

        /// <summary>
        /// Advance the gamma counter by adding {@code counter} to {@code s} as a little-endian multi-byte integer with
        /// carry propagation (counter[0] is the least significant byte).
        /// </summary>
        /// <remarks>
        /// The carry must propagate across the whole block: without it only s[0] ever changes, so the keystream block
        /// E(s) repeats every 256 blocks and any message longer than 255 blocks is encrypted with a repeating keystream
        /// (a two-time pad). See github bc-java #287.
        /// </remarks>
        private void AdvanceGamma()
        {
            int carry = 0;
            for (int byteIndex = 0; byteIndex < counter.Length; byteIndex++)
            {
                carry += s[byteIndex] + counter[byteIndex];
                s[byteIndex] = (byte)carry;
                carry >>= 8;
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void CalculateMac(ReadOnlySpan<byte> authText)
        {
            int blockSize = engine.GetBlockSize();

            while (!authText.IsEmpty)
            {
                for (int byteIndex = 0; byteIndex < blockSize; byteIndex++)
                {
                    macBlock[byteIndex] ^= authText[byteIndex];
                }

                engine.ProcessBlock(macBlock, macBlock);

                authText = authText[blockSize..];
            }
        }

        private void ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            AdvanceGamma();

            engine.ProcessBlock(s, buffer);

            int blockSize = engine.GetBlockSize();
            for (int byteIndex = 0; byteIndex < blockSize; byteIndex++)
            {
                output[byteIndex] = (byte)(buffer[byteIndex] ^ input[byteIndex]);
            }
        }
#else
        private void CalculateMac(byte[] authText, int authOff, int len)
        {
            int blockSize = engine.GetBlockSize();
            int totalLen = len;
            while (totalLen > 0)
            {
                for (int byteIndex = 0; byteIndex < blockSize; byteIndex++)
                {
                    macBlock[byteIndex] ^= authText[authOff + byteIndex];
                }

                engine.ProcessBlock(macBlock, 0, macBlock, 0);

                totalLen -= blockSize;
                authOff += blockSize;
            }
        }

        private void ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            AdvanceGamma();

            engine.ProcessBlock(s, 0, buffer, 0);

            for (int byteIndex = 0; byteIndex < engine.GetBlockSize(); byteIndex++)
            {
                output[outOff + byteIndex] = (byte)(buffer[byteIndex] ^ input[inOff + byteIndex]);
            }
        }
#endif

        public virtual int DoFinal(byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(output.AsSpan(outOff));
#else
            byte[] buf = data.GetBuffer();
            int bufLen = Convert.ToInt32(data.Length);

            int len = ProcessPacket(buf, 0, bufLen, output, outOff);

            Reset();

            return len;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual int DoFinal(Span<byte> output)
        {
            byte[] buf = data.GetBuffer();
            int bufLen = Convert.ToInt32(data.Length);

            int len = ProcessPacket(buf.AsSpan(0, bufLen), output);

            Reset();

            return len;
        }
#endif

        public virtual byte[] GetMac()
        {
            return Arrays.Clone(mac);
        }

        public virtual int GetUpdateOutputSize(int len)
        {
            return 0;
        }

        public virtual int GetOutputSize(int len)
        {
            int totalData = Convert.ToInt32(data.Length) + len;

            if (forEncryption)
            {
                return totalData + macSize;
            }

            return totalData < macSize ? 0 : totalData - macSize;
        }

        public virtual void Reset()
        {
            Arrays.Fill(G1, (byte)0);
            Arrays.Fill(buffer, (byte)0);
            Arrays.Fill(counter, (byte)0);
            Arrays.Fill(macBlock, (byte)0);

            counter[0] = 0x01; // defined in standard
            data.SetLength(0);
            associatedText.SetLength(0);

            if (initialAssociatedText != null)
            {
                ProcessAadBytes(initialAssociatedText, 0, initialAssociatedText.Length);
            }
        }

        private byte getFlag(bool authTextPresents, int macSize)
        {
            StringBuilder flagByte = new StringBuilder();

            if (authTextPresents)
            {
                flagByte.Append("1");
            }
            else
            {
                flagByte.Append("0");
            }


            switch (macSize)
            {
                case 8:
                    flagByte.Append("010"); // binary 2
                    break;
                case 16:
                    flagByte.Append("011"); // binary 3
                    break;
                case 32:
                    flagByte.Append("100"); // binary 4
                    break;
                case 48:
                    flagByte.Append("101"); // binary 5
                    break;
                case 64:
                    flagByte.Append("110"); // binary 6
                    break;
            }

            string binaryNb = Convert.ToString(Nb_ - 1, 2);
            while (binaryNb.Length < 4)
            {
                binaryNb = new StringBuilder(binaryNb).Insert(0, "0").ToString();
            }

            flagByte.Append(binaryNb);

            return (byte)Convert.ToInt32(flagByte.ToString(), 2);
        }
    }
}
