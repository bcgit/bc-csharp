using System;
using System.IO;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    public sealed class Grain128AeadEngine
        : IAeadCipher
    {
        /**
         * Constants
         */
        private static readonly int STATE_SIZE = 4;

        /**
         * Variables to hold the state of the engine during encryption and
         * decryption
         */
        private byte[] workingKey;
        private byte[] workingIV;
        private uint[] lfsr;
        private uint[] nfsr;
        private uint[] authAcc;
        private uint[] authSr;

        private bool initialised = false;
        private bool aadFinished = false;
        private MemoryStream aadData = new MemoryStream();

        private byte[] mac;

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
            /*
             * Grain encryption and decryption is completely symmetrical, so the
             * 'forEncryption' is irrelevant.
             */
            if (!(param is ParametersWithIV ivParams))
                throw new ArgumentException("Grain-128AEAD Init parameters must include an IV");

            byte[] iv = ivParams.GetIV();

            if (iv == null || iv.Length != 12)
                throw new ArgumentException("Grain-128AEAD requires exactly 12 bytes of IV");

            if (!(ivParams.Parameters is KeyParameter key))
                throw new ArgumentException("Grain-128AEAD Init parameters must include a key");

            byte[] keyBytes = key.GetKey();
            if (keyBytes.Length != 16)
                throw new ArgumentException("Grain-128AEAD key must be 128 bits long");

            /*
             * Initialize variables.
             */
            workingIV = new byte[keyBytes.Length];
            workingKey = keyBytes;
            lfsr = new uint[STATE_SIZE];
            nfsr = new uint[STATE_SIZE];
            authAcc = new uint[2];
            authSr = new uint[2];

            Array.Copy(iv, 0, workingIV, 0, iv.Length);

            Reset();
        }

        /**
         * 320 clocks initialization phase.
         */
        private void InitGrain()
        {
            for (int i = 0; i < 320; ++i)
            {
                uint outputZ = GetOutput();
                nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0] ^ outputZ) & 1);
                lfsr = Shift(lfsr, (GetOutputLFSR() ^ outputZ) & 1);
            }
            for (int quotient = 0; quotient < 8; ++quotient)
            {
                for (int remainder = 0; remainder < 8; ++remainder)
                {
                    uint outputZ = GetOutput();
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0] ^ outputZ ^ (uint)((workingKey[quotient]) >> remainder)) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR() ^ outputZ ^ (uint)((workingKey[quotient + 8]) >> remainder)) & 1);
                }
            }
            for (int quotient = 0; quotient < 2; ++quotient)
            {
                for (int remainder = 0; remainder < 32; ++remainder)
                {
                    uint outputZ = GetOutput();
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);
                    authAcc[quotient] |= outputZ << remainder;
                }
            }
            for (int quotient = 0; quotient < 2; ++quotient)
            {
                for (int remainder = 0; remainder < 32; ++remainder)
                {
                    uint outputZ = GetOutput();
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);
                    authSr[quotient] |= outputZ << remainder;
                }
            }
            initialised = true;
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

            return (b0 ^ b26 ^ b56 ^ b91 ^ b96 ^ b3 & b67 ^ b11 & b13 ^ b17 & b18
                ^ b27 & b59 ^ b40 & b48 ^ b61 & b65 ^ b68 & b84 ^ b22 & b24 & b25 ^ b70 & b78 & b82 ^ b88 & b92 & b93 & b95) & 1;
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

            return (s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96) & 1;
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
         * Shift array 1 bit and add val to index.Length - 1.
         *
         * @param array The array to shift.
         * @param val   The value to shift in.
         * @return The shifted array with val added to index.Length - 1.
         */
        private uint[] Shift(uint[] array, uint val)
        {
            array[0] = (array[0] >> 1) | (array[1] << 31);
            array[1] = (array[1] >> 1) | (array[2] << 31);
            array[2] = (array[2] >> 1) | (array[3] << 31);
            array[3] = (array[3] >> 1) | (val << 31);
            return array;
        }

        /**
         * Set keys, reset cipher.
         *
         * @param keyBytes The key.
         * @param ivBytes  The IV.
         */
        private void SetKey(byte[] keyBytes, byte[] ivBytes)
        {
            ivBytes[12] = 0xFF;
            ivBytes[13] = 0xFF;
            ivBytes[14] = 0xFF;
            ivBytes[15] = 0x7F;
            workingKey = keyBytes;
            workingIV = ivBytes;

            /*
             * Load NFSR and LFSR
             */
            Pack.LE_To_UInt32(workingKey, 0, nfsr);
            Pack.LE_To_UInt32(workingIV, 0, lfsr);
        }

        public int ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            Check.DataLength(input, inOff, len, "input buffer too short");
            Check.OutputLength(output, outOff, len, "output buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessBytes(input.AsSpan(inOff, len), output.AsSpan(outOff));
#else
            if (!initialised)
                throw new ArgumentException(AlgorithmName + " not initialised");

            if (!aadFinished)
            {
                DoProcessAADBytes(aadData.GetBuffer(), 0, (int)aadData.Length);
                aadFinished = true;
            }

            GetKeyStream(input, inOff, len, output, outOff);
            return len;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Check.OutputLength(output, input.Length, "output buffer too short");

            if (!initialised)
                throw new ArgumentException(AlgorithmName + " not initialised");

            if (!aadFinished)
            {
                DoProcessAADBytes(aadData.GetBuffer(), 0, (int)aadData.Length);
                aadFinished = true;
            }

            GetKeyStream(input, output);
            return input.Length;
        }
#endif

        public void Reset()
        {
            Reset(true);
        }

        private void Reset(bool clearMac)
        {
            if (clearMac)
            {
                this.mac = null;
            }
            this.aadData.SetLength(0);
            this.aadFinished = false;

            SetKey(workingKey, workingIV);
            InitGrain();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void GetKeyStream(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int len = input.Length;
            for (int i = 0; i < len; ++i)
            {
                uint cc = 0, input_i = input[i];
                for (int j = 0; j < 8; ++j)
                {
                    uint outputZ = GetOutput();
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);

                    uint input_i_j = (input_i >> j) & 1U;
                    cc |= (input_i_j ^ outputZ) << j;

                    //if (input_i_j != 0)
                    //{
                    //    Accumulate();
                    //}
                    uint mask = 0U - input_i_j;
                    authAcc[0] ^= authSr[0] & mask;
                    authAcc[1] ^= authSr[1] & mask;

                    AuthShift(GetOutput());
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);
                }
                output[i] = (byte)cc;
            }
        }
#else
        private void GetKeyStream(byte[] input, int inOff, int len, byte[] ciphertext, int outOff)
        {
            for (int i = 0; i < len; ++i)
            {
                uint cc = 0, input_i = input[inOff + i];
                for (int j = 0; j < 8; ++j)
                {
                    uint outputZ = GetOutput();
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);

                    uint input_i_j = (input_i >> j) & 1U;
                    cc |= (input_i_j ^ outputZ) << j;

                    //if (input_i_j != 0)
                    //{
                    //    Accumulate();
                    //}
                    uint mask = 0U - input_i_j;
                    authAcc[0] ^= authSr[0] & mask;
                    authAcc[1] ^= authSr[1] & mask;

                    AuthShift(GetOutput());
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);
                }
                ciphertext[outOff + i] = (byte)cc;
            }
        }
#endif

        public byte ReturnByte(byte input)
        {
            if (!initialised)
                throw new ArgumentException(AlgorithmName + " not initialised");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> plaintext = stackalloc byte[1]{ input };
            Span<byte> ciphertext = stackalloc byte[1];
            GetKeyStream(plaintext, ciphertext);
            return ciphertext[0];
#else
            byte[] plaintext = new byte[1]{ input };
            byte[] ciphertext = new byte[1];
            GetKeyStream(plaintext, 0, 1, ciphertext, 0);
            return ciphertext[0];
#endif
        }

        public void ProcessAadByte(byte input)
        {
            if (aadFinished)
                throw new ArgumentException("associated data must be added before plaintext/ciphertext");

            aadData.WriteByte(input);
        }

        public void ProcessAadBytes(byte[] input, int inOff, int len)
        {
            if (aadFinished)
                throw new ArgumentException("associated data must be added before plaintext/ciphertext");

            aadData.Write(input, inOff, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            if (aadFinished)
                throw new ArgumentException("associated data must be added before plaintext/ciphertext");

            aadData.Write(input);
        }
#endif

        private void Accumulate()
        {
            authAcc[0] ^= authSr[0];
            authAcc[1] ^= authSr[1];
        }

        private void AuthShift(uint val)
        {
            authSr[0] = (authSr[0] >> 1) | (authSr[1] << 31);
            authSr[1] = (authSr[1] >> 1) | (val << 31);
        }

        public int ProcessByte(byte input, byte[] output, int outOff)
        {
            return ProcessBytes(new byte[]{ input }, 0, 1, output, outOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessByte(byte input, Span<byte> output)
        {
            return ProcessBytes(stackalloc byte[1]{ input }, output);
        }
#endif

        private void DoProcessAADBytes(byte[] input, int inOff, int len)
        {
            byte[] ader;
            int aderlen;
            //encodeDer
            if (len < 128)
            {
                ader = new byte[1 + len];
                ader[0] = (byte)len;
                aderlen = 0;
            }
            else
            {
                // aderlen is the highest bit position divided by 8
                aderlen = LenLength(len);
                ader = new byte[aderlen + 1 + len];
                ader[0] = (byte)(0x80 | (uint)aderlen);
                uint tmp = (uint)len;
                for (int i = 0; i < aderlen; ++i)
                {
                    ader[1 + i] = (byte)tmp;
                    tmp >>= 8;
                }
            }
            for (int i = 0; i < len; ++i)
            {
                ader[1 + aderlen + i] = input[inOff + i];
            }

            for (int i = 0; i < ader.Length; ++i)
            {
                uint ader_i = ader[i];
                for (int j = 0; j < 8; ++j)
                {
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);

                    uint ader_i_j = (ader_i >> j) & 1U;
                    //if (ader_i_j != 0)
                    //{
                    //    Accumulate();
                    //}
                    uint mask = 0U - ader_i_j;
                    authAcc[0] ^= authSr[0] & mask;
                    authAcc[1] ^= authSr[1] & mask;

                    AuthShift(GetOutput());
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);
                }
            }
        }

        public int DoFinal(byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(output.AsSpan(outOff));
#else
            if (!aadFinished)
            {
                DoProcessAADBytes(aadData.GetBuffer(), 0, (int)aadData.Length);
                aadFinished = true;
            }

            Accumulate();

            this.mac = Pack.UInt32_To_LE(authAcc);

            Array.Copy(mac, 0, output, outOff, mac.Length);

            Reset(false);

            return mac.Length;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            if (!aadFinished)
            {
                DoProcessAADBytes(aadData.GetBuffer(), 0, (int)aadData.Length);
                aadFinished = true;
            }

            Accumulate();

            this.mac = Pack.UInt32_To_LE(authAcc);

            mac.CopyTo(output);

            Reset(false);

            return mac.Length;
        }
#endif

        public byte[] GetMac()
        {
            return mac;
        }

        public int GetUpdateOutputSize(int len)
        {
            return len;
        }

        public int GetOutputSize(int len)
        {
            return len + 8;
        }

        private static int LenLength(int v)
        {
            if ((v & 0xff) == v)
                return 1;

            if ((v & 0xffff) == v)
                return 2;

            if ((v & 0xffffff) == v)
                return 3;

            return 4;
        }
    }
}
