using System;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    public sealed class Grain128AeadEngine
        : IAeadCipher
    {
        private enum State
        {
            Uninitialized  = 0,
            EncInit        = 1,
            EncAad         = 2,
            EncData        = 3,
            EncFinal       = 4,
            DecInit        = 5,
            DecAad         = 6,
            DecData        = 7,
            DecFinal       = 8,
        }

        private const int BufSize = 64;
        private const int KeySize = 16;
        private const int IVSize = 12;
        private const int MacSize = 8;

        /**
         * Variables to hold the state of the engine during encryption and
         * decryption
         */
        private readonly byte[] workingKeyAndIV = new byte[KeySize + IVSize];
        private readonly uint[] lfsr = new uint[4];
        private readonly uint[] nfsr = new uint[4];
        private readonly uint[] authAccSr = new uint[4];

        private State m_state = State.Uninitialized;

        private readonly MemoryStream m_aadData = new MemoryStream();
        private readonly byte[] m_mac = new byte[MacSize];
        private readonly byte[] m_buf = new byte[BufSize + MacSize];
        private int m_bufPos;

        public Grain128AeadEngine()
        {
            m_aadData.Position = 5;
        }

        public string AlgorithmName => "Grain-128AEAD";

        /**
         * Initialize a Grain-128AEAD cipher.
         *
         * @param forEncryption Whether or not we are for encryption.
         * @param param        The parameters required to set up the cipher.
         * @throws ArgumentException If the params argument is inappropriate.
         */
        public void Init(bool forEncryption, ICipherParameters param)
        {
            // TODO Support AeadParameters

            if (!(param is ParametersWithIV withIV))
                throw new ArgumentException("Grain-128AEAD Init parameters must include an IV");

            if (withIV.IVLength != IVSize)
                throw new ArgumentException("Grain-128AEAD requires exactly 12 bytes of IV");

            if (!(withIV.Parameters is KeyParameter key))
                throw new ArgumentException("Grain-128AEAD Init parameters must include a key");

            if (key.KeyLength != KeySize)
                throw new ArgumentException("Grain-128AEAD key must be 128 bits long");

            // TODO Support key re-use (via null KeyParameters)

            // TODO Check for encryption with reused nonce

            key.CopyKeyTo(workingKeyAndIV, 0, KeySize);
            withIV.CopyIVTo(workingKeyAndIV, KeySize, IVSize);

            m_state = forEncryption ? State.EncInit : State.DecInit;

            Reset();
        }

        public int GetOutputSize(int len)
        {
            int total = System.Math.Max(0, len);

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                return System.Math.Max(0, total - MacSize);
            case State.DecData:
            case State.DecFinal:
                return System.Math.Max(0, total + m_bufPos - MacSize);
            case State.EncData:
            case State.EncFinal:
                return total + m_bufPos + MacSize;
            default:
                return total + MacSize;
            }
        }

        public int GetUpdateOutputSize(int len)
        {
            int total = System.Math.Max(0, len);

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                total = System.Math.Max(0, total - MacSize);
                break;
            case State.DecData:
            case State.DecFinal:
                total = System.Math.Max(0, total + m_bufPos - MacSize);
                break;
            case State.EncData:
            case State.EncFinal:
                total += m_bufPos;
                break;
            default:
                break;
            }

            return total - total % BufSize;
        }

        public void ProcessAadByte(byte input)
        {
            CheckAad();

            m_aadData.WriteByte(input);
        }

        public void ProcessAadBytes(byte[] input, int inOff, int len)
        {
            // TODO More argument checks?

            Check.DataLength(input, inOff, len, "input buffer too short");

            CheckAad();

            m_aadData.Write(input, inOff, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            CheckAad();

            m_aadData.Write(input);
        }
#endif

        public int ProcessByte(byte input, byte[] output, int outOff) =>
            ProcessBytes(new byte[1]{ input }, 0, 1, output, outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessByte(byte input, Span<byte> output) => ProcessBytes(stackalloc byte[1]{ input }, output);
#endif

        public int ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            // TODO More argument checks?

            Check.DataLength(input, inOff, len, "input buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessBytes(input.AsSpan(inOff, len), output.AsSpan(outOff));
#else
            int updateOutputSize = GetUpdateOutputSize(len);
            Check.OutputLength(output, outOff, updateOutputSize, "output buffer too short");

            CheckData();

            switch (m_state)
            {
            case State.DecData:
            {
                for (int i = 0; i < len; ++i)
                {
                    m_buf[m_bufPos] = input[inOff + i];
                    if (++m_bufPos == m_buf.Length)
                    {
                        ProcessBufferDecrypt(m_buf, 0, BufSize, output, outOff);
                        outOff += BufSize;

                        Debug.Assert(BufSize >= MacSize);
                        Array.Copy(m_buf, BufSize, m_buf, 0, MacSize);
                        m_bufPos = MacSize;
                    }
                }
                break;
            }
            case State.EncData:
            {
                for (int i = 0; i < len; ++i)
                {
                    m_buf[m_bufPos] = input[inOff + i];
                    if (++m_bufPos == BufSize)
                    {
                        ProcessBufferEncrypt(m_buf, 0, BufSize, output, outOff);
                        outOff += BufSize;

                        m_bufPos = 0;
                    }
                }
                break;
            }
            default:
                throw new InvalidOperationException();
            }

            return updateOutputSize;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int updateOutputSize = GetUpdateOutputSize(input.Length);
            Check.OutputLength(output, updateOutputSize, "output buffer too short");

            CheckData();

            switch (m_state)
            {
            case State.DecData:
            {
                for (int i = 0; i < input.Length; ++i)
                {
                    m_buf[m_bufPos] = input[i];
                    if (++m_bufPos == m_buf.Length)
                    {
                        ProcessBufferDecrypt(m_buf.AsSpan(0, BufSize), output);
                        output = output[BufSize..];

                        Debug.Assert(BufSize >= MacSize);
                        Array.Copy(m_buf, BufSize, m_buf, 0, MacSize);
                        m_bufPos = MacSize;
                    }
                }
                break;
            }
            case State.EncData:
            {
                for (int i = 0; i < input.Length; ++i)
                {
                    m_buf[m_bufPos] = input[i];
                    if (++m_bufPos == BufSize)
                    {
                        ProcessBufferEncrypt(m_buf.AsSpan(0, BufSize), output);
                        output = output[BufSize..];

                        m_bufPos = 0;
                    }
                }
                break;
            }
            default:
                throw new InvalidOperationException();
            }

            return updateOutputSize;
        }
#endif

        public int DoFinal(byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(output.AsSpan(outOff));
#else
            int outputSize = GetOutputSize(0);
            Check.OutputLength(output, outOff, outputSize, "output buffer too short");

            CheckData();

            switch (m_state)
            {
            case State.DecData:
            {
                if (m_bufPos < MacSize)
                    throw new InvalidCipherTextException("data too short");

                if (outputSize > 0)
                {
                    ProcessBufferDecrypt(m_buf, 0, outputSize, output, outOff);
                    //outOff += outputSize;
                }

                FinishData(State.DecFinal);

                if (!Arrays.FixedTimeEquals(MacSize, m_mac, 0, m_buf, outputSize))
                    throw new InvalidCipherTextException("mac check in " + AlgorithmName + " failed");

                break;
            }
            case State.EncData:
            {
                if (m_bufPos > 0)
                {
                    ProcessBufferEncrypt(m_buf, 0, m_bufPos, output, outOff);
                    outOff += m_bufPos;
                }

                FinishData(State.EncFinal);

                Array.Copy(m_mac, 0, output, outOff, MacSize);
                break;
            }
            }

            Reset(false);
            return outputSize;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            int outputSize = GetOutputSize(0);
            Check.OutputLength(output, outputSize, "output buffer too short");

            CheckData();

            switch (m_state)
            {
            case State.DecData:
            {
                if (m_bufPos < MacSize)
                    throw new InvalidCipherTextException("data too short");

                if (outputSize > 0)
                {
                    ProcessBufferDecrypt(m_buf.AsSpan(0, outputSize), output);
                    //output = output[outputSize..];
                }

                FinishData(State.DecFinal);

                if (!Arrays.FixedTimeEquals(MacSize, m_mac, 0, m_buf, outputSize))
                    throw new InvalidCipherTextException("mac check in " + AlgorithmName + " failed");

                break;
            }
            case State.EncData:
            {
                if (m_bufPos > 0)
                {
                    ProcessBufferEncrypt(m_buf.AsSpan(0, m_bufPos), output);
                    output = output[m_bufPos..];
                }

                FinishData(State.EncFinal);

                m_mac.CopyTo(output);
                break;
            }
            }

            Reset(false);
            return outputSize;
        }
#endif

        public byte[] GetMac() => (byte[])m_mac.Clone();

        public void Reset() => Reset(true);

        // TODO[api] Remove ASAP
        [Obsolete("Incompatible with the AEAD API; throws NotImplementedException")]
        public byte ReturnByte(byte input) => throw new NotImplementedException();

        private void CheckAad()
        {
            switch (m_state)
            {
            case State.DecInit:
                m_state = State.DecAad;
                break;
            case State.EncInit:
                m_state = State.EncAad;
                break;
            case State.DecAad:
            case State.EncAad:
                break;
            case State.DecData:
            case State.EncData:
                // TODO[api] Consider changing the error message (specialize for DecData vs EncData?)
                throw new InvalidOperationException("associated data must be added before plaintext/ciphertext");
            case State.EncFinal:
                throw new InvalidOperationException(AlgorithmName + " cannot be reused for encryption");
            default:
                throw new InvalidOperationException(AlgorithmName + " needs to be initialized");
            }
        }

        private void CheckData()
        {
            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                FinishAad(State.DecData);
                break;
            case State.EncInit:
            case State.EncAad:
                FinishAad(State.EncData);
                break;
            case State.DecData:
            case State.EncData:
                break;
            case State.EncFinal:
                throw new InvalidOperationException(AlgorithmName + " cannot be reused for encryption");
            default:
                throw new InvalidOperationException(AlgorithmName + " needs to be initialized");
            }
        }

        private void FinishAad(State nextState)
        {
            // Encode(ad length) denotes the message length encoded in the DER format.

            // The first 5 bytes of the buffer were preallocated to give us space for the DER length
            byte[] buffer = m_aadData.GetBuffer();
            int length = Convert.ToInt32(m_aadData.Length);
            int aadLen = length - 5;

            int pos;
            if (aadLen < 128)
            {
                pos = 4;
                buffer[pos] = (byte)aadLen;
            }
            else
            {
                pos = 5;

                uint dl = (uint)aadLen;
                do
                {
                    buffer[--pos] = (byte)dl;
                    dl >>= 8;
                }
                while (dl > 0);

                int count = 5 - pos;
                buffer[--pos] = (byte)(0x80 | count);
            }

            for (int i = pos; i < length; ++i)
            {
                uint b = buffer[i];

                for (int j = 0; j < 8; ++j)
                {
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());

                    uint ader_i_j = (b >> j) & 1U;

                    uint mask = 0U - ader_i_j;
                    authAccSr[0] ^= authAccSr[2] & mask;
                    authAccSr[1] ^= authAccSr[3] & mask;

                    ShiftAuth(GetOutput());
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());
                }
            }

            m_state = nextState;
        }

        private void FinishData(State nextState)
        {
            authAccSr[0] ^= authAccSr[2];
            authAccSr[1] ^= authAccSr[3];

            Pack.UInt32_To_LE(authAccSr, 0, 2, m_mac, 0);

            m_state = nextState;
        }

        /**
         * Get output from output function h(x).
         *
         * @return y_t.
         */
        private uint GetOutput()
        {
            uint b2 = nfsr[0] >> 2;
            uint b12 = nfsr[0] >> 12;
            uint b15 = nfsr[0] >> 15;
            uint b36 = nfsr[1] >> 4;
            uint b45 = nfsr[1] >> 13;
            uint b64 = nfsr[2];
            uint b73 = nfsr[2] >> 9;
            uint b89 = nfsr[2] >> 25;
            uint b95 = nfsr[2] >> 31;
            uint s8 = lfsr[0] >> 8;
            uint s13 = lfsr[0] >> 13;
            uint s20 = lfsr[0] >> 20;
            uint s42 = lfsr[1] >> 10;
            uint s60 = lfsr[1] >> 28;
            uint s79 = lfsr[2] >> 15;
            uint s93 = lfsr[2] >> 29;
            uint s94 = lfsr[2] >> 30;

            return ((b12 & s8) ^ (s13 & s20) ^ (b95 & s42) ^ (s60 & s79) ^ (b12 & b95 & s94) ^ s93
                ^ b2 ^ b15 ^ b36 ^ b45 ^ b64 ^ b73 ^ b89) & 1;
        }

        /**
         * Get output from linear function f(x).
         *
         * @return Output from LFSR.
         */
        private uint GetOutputLFSR()
        {
            uint s0 = lfsr[0];
            uint s7 = lfsr[0] >> 7;
            uint s38 = lfsr[1] >> 6;
            uint s70 = lfsr[2] >> 6;
            uint s81 = lfsr[2] >> 17;
            uint s96 = lfsr[3];

            return s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96;
        }

        /**
         * Get output from non-linear function g(x).
         *
         * @return Output from NFSR.
         */
        private uint GetOutputNFSR()
        {
            uint b0 = nfsr[0];
            uint b3 = nfsr[0] >> 3;
            uint b11 = nfsr[0] >> 11;
            uint b13 = nfsr[0] >> 13;
            uint b17 = nfsr[0] >> 17;
            uint b18 = nfsr[0] >> 18;
            uint b22 = nfsr[0] >> 22;
            uint b24 = nfsr[0] >> 24;
            uint b25 = nfsr[0] >> 25;
            uint b26 = nfsr[0] >> 26;
            uint b27 = nfsr[0] >> 27;
            uint b40 = nfsr[1] >> 8;
            uint b48 = nfsr[1] >> 16;
            uint b56 = nfsr[1] >> 24;
            uint b59 = nfsr[1] >> 27;
            uint b61 = nfsr[1] >> 29;
            uint b65 = nfsr[2] >> 1;
            uint b67 = nfsr[2] >> 3;
            uint b68 = nfsr[2] >> 4;
            uint b70 = nfsr[2] >> 6;
            uint b78 = nfsr[2] >> 14;
            uint b82 = nfsr[2] >> 18;
            uint b84 = nfsr[2] >> 20;
            uint b88 = nfsr[2] >> 24;
            uint b91 = nfsr[2] >> 27;
            uint b92 = nfsr[2] >> 28;
            uint b93 = nfsr[2] >> 29;
            uint b95 = nfsr[2] >> 31;
            uint b96 = nfsr[3];

            return b0 ^ b26 ^ b56 ^ b91 ^ b96 ^ b3 & b67 ^ b11 & b13 ^ b17 & b18 ^ b27 & b59 ^ b40 & b48 ^ b61 & b65
                ^ b68 & b84 ^ b22 & b24 & b25 ^ b70 & b78 & b82 ^ b88 & b92 & b93 & b95;
        }

        private void InitGrain()
        {
            Pack.LE_To_UInt32(workingKeyAndIV, 0, nfsr, 0, 4);
            Pack.LE_To_UInt32(workingKeyAndIV, KeySize, lfsr, 0, 3);
            lfsr[3] = 0x7FFFFFFFU;

            for (int i = 0; i < 320; ++i)
            {
                uint outputZ = GetOutput();
                ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0] ^ outputZ);
                ShiftBit(lfsr, GetOutputLFSR() ^ outputZ);
            }
            for (int quotient = 0; quotient < 8; ++quotient)
            {
                uint wk0 = (uint)workingKeyAndIV[quotient];
                uint wk8 = (uint)workingKeyAndIV[quotient + 8];

                for (int remainder = 0; remainder < 8; ++remainder)
                {
                    uint outputZ = GetOutput();
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0] ^ outputZ ^ (wk0 >> remainder));
                    ShiftBit(lfsr, GetOutputLFSR() ^ outputZ ^ (wk8 >> remainder));
                }
            }
            for (int j = 0; j < 4; ++j)
            {
                uint t = 0;
                for (int remainder = 0; remainder < 32; ++remainder)
                {
                    uint outputZ = GetOutput();
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());
                    t |= outputZ << remainder;
                }
                authAccSr[j] = t;
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void ProcessBufferDecrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            for (int i = 0, len = input.Length; i < len; ++i)
            {
                uint ct_i = input[i], pt_i = 0;
                for (int j = 0; j < 8; ++j)
                {
                    uint ct_i_j = (ct_i >> j) & 1U;

                    uint pt_i_j = ct_i_j ^ GetOutput();
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());

                    pt_i |= pt_i_j << j;

                    uint mask = 0U - pt_i_j;
                    authAccSr[0] ^= authAccSr[2] & mask;
                    authAccSr[1] ^= authAccSr[3] & mask;

                    ShiftAuth(GetOutput());
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());
                }
                output[i] = (byte)pt_i;
            }
        }

        private void ProcessBufferEncrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            for (int i = 0, len = input.Length; i < len; ++i)
            {
                uint ct_i = 0, pt_i = input[i];
                for (int j = 0; j < 8; ++j)
                {
                    uint pt_i_j = (pt_i >> j) & 1U;

                    uint ct_i_j = pt_i_j ^ GetOutput();
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());

                    ct_i |= ct_i_j << j;

                    uint mask = 0U - pt_i_j;
                    authAccSr[0] ^= authAccSr[2] & mask;
                    authAccSr[1] ^= authAccSr[3] & mask;

                    ShiftAuth(GetOutput());
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());
                }
                output[i] = (byte)ct_i;
            }
        }
#else
        private void ProcessBufferDecrypt(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            for (int i = 0; i < len; ++i)
            {
                uint ct_i = input[inOff + i], pt_i = 0;
                for (int j = 0; j < 8; ++j)
                {
                    uint ct_i_j = (ct_i >> j) & 1U;

                    uint pt_i_j = ct_i_j ^ GetOutput();
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());

                    pt_i |= pt_i_j << j;

                    uint mask = 0U - pt_i_j;
                    authAccSr[0] ^= authAccSr[2] & mask;
                    authAccSr[1] ^= authAccSr[3] & mask;

                    ShiftAuth(GetOutput());
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());
                }
                output[outOff + i] = (byte)pt_i;
            }
        }

        private void ProcessBufferEncrypt(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            for (int i = 0; i < len; ++i)
            {
                uint ct_i = 0, pt_i = input[inOff + i];
                for (int j = 0; j < 8; ++j)
                {
                    uint pt_i_j = (pt_i >> j) & 1U;

                    uint ct_i_j = pt_i_j ^ GetOutput();
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());

                    ct_i |= ct_i_j << j;

                    uint mask = 0U - pt_i_j;
                    authAccSr[0] ^= authAccSr[2] & mask;
                    authAccSr[1] ^= authAccSr[3] & mask;

                    ShiftAuth(GetOutput());
                    ShiftBit(nfsr, GetOutputNFSR() ^ lfsr[0]);
                    ShiftBit(lfsr, GetOutputLFSR());
                }
                output[outOff + i] = (byte)ct_i;
            }
        }
#endif

        private void Reset(bool clearMac)
        {
            m_aadData.SetLength(5);

            if (clearMac)
            {
                Array.Clear(m_mac, 0, m_mac.Length);
            }

            Array.Clear(m_buf, 0, m_buf.Length);
            m_bufPos = 0;

            switch (m_state)
            {
            case State.DecInit:
            case State.EncInit:
                break;
            case State.DecAad:
            case State.DecData:
            case State.DecFinal:
                m_state = State.DecInit;
                break;
            case State.EncAad:
            case State.EncData:
            case State.EncFinal:
                m_state = State.EncFinal;
                return;
            default:
                throw new InvalidOperationException(AlgorithmName + " needs to be initialized");
            }

            InitGrain();
        }

        private void ShiftAuth(uint val)
        {
            authAccSr[2] = (authAccSr[2] >> 1) | (authAccSr[3] << 31);
            authAccSr[3] = (authAccSr[3] >> 1) | (val << 31);
        }

        /**
         * Shift array 1 bit and add val to index.Length - 1.
         *
         * @param array The array to shift.
         * @param val   The value to shift in.
         * @return The shifted array with val added to index.Length - 1.
         */
        private void ShiftBit(uint[] array, uint val)
        {
            array[0] = (array[0] >> 1) | (array[1] << 31);
            array[1] = (array[1] >> 1) | (array[2] << 31);
            array[2] = (array[2] >> 1) | (array[3] << 31);
            array[3] = (array[3] >> 1) | (val << 31);
        }
    }
}
