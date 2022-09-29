using System;
using System.IO;
using System.Numerics;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    public class Grain128AeadEngine//: AeadCipher
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
        private uint outputZ;

        private bool initialised = false;
        private bool isEven = true; // zero treated as even
        private bool aadFinished = false;
        private MemoryStream aadData = new MemoryStream();

        private byte[] mac;


        public String GetAlgorithmName()
        {
            return "Grain-128AEAD";
        }

        /**
         * Initialize a Grain-128AEAD cipher.
         *
         * @param forEncryption Whether or not we are for encryption.
         * @param param        The parameters required to set up the cipher.
         * @throws ArgumentException If the params argument is inappropriate.
         */
        public void Init(bool forEncryption, ICipherParameters param)
        {
            /**
             * Grain encryption and decryption is completely symmetrical, so the
             * 'forEncryption' is irrelevant.
             */
            if (!(param is ParametersWithIV))
            {
                throw new ArgumentException(
                    "Grain-128AEAD Init parameters must include an IV");
            }

            ParametersWithIV ivParams = (ParametersWithIV)param;

            byte[]
            iv = ivParams.GetIV();

            if (iv == null || iv.Length != 12)
            {
                throw new ArgumentException(
                    "Grain-128AEAD requires exactly 12 bytes of IV");
            }

            if (!(ivParams.Parameters is KeyParameter))
            {
                throw new ArgumentException(
                    "Grain-128AEAD Init parameters must include a key");
            }

            KeyParameter key = (KeyParameter)ivParams.Parameters;
            byte[] keyBytes = key.GetKey();
            if (keyBytes.Length != 16)
            {
                throw new ArgumentException(
                    "Grain-128AEAD key must be 128 bits long");
            }
            /**
             * Initialize variables.
             */
            workingIV = new byte[key.GetKey().Length];
            workingKey = new byte[key.GetKey().Length];
            lfsr = new uint[STATE_SIZE];
            nfsr = new uint[STATE_SIZE];
            authAcc = new uint[2];
            authSr = new uint[2];


            Array.Copy(iv, 0, workingIV, 0, iv.Length);
            Array.Copy(key.GetKey(), 0, workingKey, 0, key.GetKey().Length);

            Reset();
        }

        /**
         * 320 clocks initialization phase.
         */
        private void InitGrain()
        {
            for (int i = 0; i < 320; ++i)
            {
                outputZ = GetOutput();
                nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0] ^ outputZ) & 1);
                lfsr = Shift(lfsr, (GetOutputLFSR() ^ outputZ) & 1);
            }
            for (int quotient = 0; quotient < 8; ++quotient)
            {
                for (int remainder = 0; remainder < 8; ++remainder)
                {
                    outputZ = GetOutput();
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0] ^ outputZ ^ (uint)((workingKey[quotient]) >> remainder)) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR() ^ outputZ ^ (uint)((workingKey[quotient + 8]) >> remainder)) & 1);
                }
            }
            for (int quotient = 0; quotient < 2; ++quotient)
            {
                for (int remainder = 0; remainder < 32; ++remainder)
                {
                    outputZ = GetOutput();
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);
                    authAcc[quotient] |= outputZ << remainder;
                }
            }
            for (int quotient = 0; quotient < 2; ++quotient)
            {
                for (int remainder = 0; remainder < 32; ++remainder)
                {
                    outputZ = GetOutput();
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
            ivBytes[12] = (byte)0xFF;
            ivBytes[13] = (byte)0xFF;
            ivBytes[14] = (byte)0xFF;
            ivBytes[15] = (byte)0x7F;//(byte) 0xFE;
            workingKey = keyBytes;
            workingIV = ivBytes;

            /**
             * Load NFSR and LFSR
             */
            int j = 0;
            for (int i = 0; i < nfsr.Length; i++)
            {
                nfsr[i] = (uint)(((workingKey[j + 3]) << 24) | ((workingKey[j + 2]) << 16)
                    & 0x00FF0000 | ((workingKey[j + 1]) << 8) & 0x0000FF00
                    | ((workingKey[j]) & 0x000000FF));

                lfsr[i] = (uint)(((workingIV[j + 3]) << 24) | ((workingIV[j + 2]) << 16)
                    & 0x00FF0000 | ((workingIV[j + 1]) << 8) & 0x0000FF00
                    | ((workingIV[j]) & 0x000000FF));
                j += 4;
            }
        }

        public int ProcessBytes(byte[] input, int inOff, int len, byte[] output,
                                int outOff)
        {
            if (!initialised)
            {
                throw new ArgumentException(GetAlgorithmName()
                    + " not initialised");
            }
            if (!aadFinished)
            {
                DoProcessAADBytes(aadData.GetBuffer(), 0, (int)aadData.Length);
                aadFinished = true;
            }


            if ((inOff + len) > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }

            if ((outOff + len) > output.Length)
            {
                throw new OutputLengthException("output buffer too short");
            }
            GetKeyStream(input, inOff, len, output, outOff);
            return len;
        }

        public void Reset()
        {
            this.isEven = true;
            this.mac = null;
            this.aadData.SetLength(0);
            this.aadFinished = false;

            SetKey(workingKey, workingIV);
            InitGrain();
        }

        private byte[] GetKeyStream(byte[] input, int inOff, int len, byte[] ciphertext, int outOff)
        {
            int mCnt = 0, acCnt = 0, cCnt = 0;
            byte cc;
            byte[] plaintext = new byte[len];
            for (int i = 0; i < len; ++i)
            {
                plaintext[i] = (byte)ReverseByte(input[inOff + i]);
            }
            for (int i = 0; i < len; ++i)
            {
                cc = 0;
                for (int j = 0; j < 16; ++j)
                {
                    outputZ = GetOutput();
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);
                    if (isEven)
                    {
                        cc |= (byte)(((((plaintext[mCnt >> 3]) >> (7 - (mCnt & 7))) & 1) ^ outputZ) << (cCnt & 7));
                        mCnt++;
                        cCnt++;
                        isEven = false;
                    }
                    else
                    {

                        if ((plaintext[acCnt >> 3] & (1 << (7 - (acCnt & 7)))) != 0)
                        {
                            Accumulate();
                        }
                        AuthShift(outputZ);
                        acCnt++;
                        isEven = true;
                    }
                }
                ciphertext[outOff + i] = cc;
            }
            //outputZ = GetOutput();
            //nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
            //lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);
            //Accumulate();
            //cCnt = len + outOff;//acc_idx
            //for (int i = 0; i < 2; ++i)
            //{
            //    for (int j = 0; j < 4; ++j)
            //    {
            //        ciphertext[cCnt] = (byte)((authAcc[i] >> (j << 3)) & 0xff);
            //        cCnt++;
            //    }
            //}

            return ciphertext;
        }


        public byte ReturnByte(byte input)
        {
            if (!initialised)
            {
                throw new ArgumentException(GetAlgorithmName()
                    + " not initialised");
            }
            byte[] plaintext = new byte[1];
            plaintext[0] = input;
            byte[] ciphertext = new byte[1];
            return GetKeyStream(plaintext, 0, 1, ciphertext, 0)[0];
        }


        public void ProcessAADByte(byte input)
        {
            if (aadFinished)
            {
                throw new ArgumentException("associated data must be added before plaintext/ciphertext");
            }
            aadData.Write(new byte[] { input }, 0, 1);

        }

        public void ProcessAADBytes(byte[] input, int inOff, int len)
        {
            if (aadFinished)
            {
                throw new ArgumentException("associated data must be added before plaintext/ciphertext");
            }
            aadData.Write(input, inOff, len);
        }

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
            return ProcessBytes(new byte[] { input }, 0, 1, output, outOff);
        }

        private void DoProcessAADBytes(byte[] input, int inOff, int len)
        {
            byte[] ader;
            int aderlen;
            //encodeDer
            if (len < 128)
            {
                ader = new byte[1 + len];
                ader[0] = (byte)ReverseByte((uint)len);
                aderlen = 0;
            }
            else
            {
                aderlen = LenLength(len);
                ader = new byte[aderlen + 1 + len];
                ader[0] = (byte)ReverseByte(0x80 | (uint)aderlen);
                uint tmp = (uint)len;
                for (int i = 0; i < aderlen; ++i)
                {
                    ader[1 + i] = (byte)ReverseByte(tmp & 0xff);
                    tmp >>= 8;
                }
            }
            for (int i = 0; i < len; ++i)
            {
                ader[1 + aderlen + i] = (byte)ReverseByte(input[inOff + i]);
            }
            byte adval;
            int adCnt = 0;
            for (int i = 0; i < ader.Length; ++i)
            {
                for (int j = 0; j < 16; ++j)
                {
                    outputZ = GetOutput();
                    nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
                    lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);
                    if ((j & 1) == 1)
                    {
                        adval = (byte)(ader[adCnt >> 3] & (1 << (7 - (adCnt & 7))));
                        if (adval != 0)
                        {
                            Accumulate();
                        }
                        AuthShift(outputZ);
                        adCnt++;
                    }
                }
            }


        }

        private int LenLength(int v)
        {
            if ((v & 0xff) == v)
            {
                return 1;
            }
            if ((v & 0xffff) == v)
            {
                return 2;
            }
            if ((v & 0xffffff) == v)
            {
                return 3;
            }

            return 4;
        }

        public int DoFinal(byte[] output, int outOff)
        {
            if (!aadFinished)
            {
                DoProcessAADBytes(aadData.GetBuffer(), 0, (int)aadData.Length);
                aadFinished = true;
            }

            this.mac = new byte[8];

            outputZ = GetOutput();
            nfsr = Shift(nfsr, (GetOutputNFSR() ^ lfsr[0]) & 1);
            lfsr = Shift(lfsr, (GetOutputLFSR()) & 1);
            Accumulate();

            int cCnt = 0;
            for (int i = 0; i < 2; ++i)
            {
                for (int j = 0; j < 4; ++j)
                {
                    mac[cCnt++] = (byte)((authAcc[i] >> (j << 3)) & 0xff);
                }
            }

            Array.Copy(mac, 0, output, outOff, mac.Length);

            try
            {
                return mac.Length;
            }
            finally
            {
                Reset();
            }

        }


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

        private uint ReverseByte(uint x)
        {
            x = (uint)(((x & 0x55) << 1) | ((x & (~0x55)) >> 1)) & 0xFF;
            x = (uint)(((x & 0x33) << 2) | ((x & (~0x33)) >> 2)) & 0xFF;
            x = (uint)(((x & 0x0f) << 4) | ((x & (~0x0f)) >> 4)) & 0xFF;
            return x;
        }

        public uint HighestOneBit(uint v)
        {
            int[] MultiplyDeBruijnBitPosition ={
      0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
      8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31
   };
            v |= v >> 1;
            v |= v >> 2;
            v |= v >> 4;
            v |= v >> 8;
            v |= v >> 16;

            return (uint)(1 << MultiplyDeBruijnBitPosition[(v * 0x07C4ACDDU) >> 27]);
        }
    }
}

