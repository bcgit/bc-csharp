using System;
using System.IO;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
/**
* Xoodyak v1, https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
* <p>
* Xoodyak with reference to C Reference Impl from: https://github.com/XKCP/XKCP
* </p>
*/
namespace Org.BouncyCastle.Crypto.Engines
{
    public sealed class XoodyakEngine : IAeadBlockCipher
    {
        private bool forEncryption;
        private byte[] state;
        private int phase;
        private MODE mode;
        private int Rabsorb;
        private const int f_bPrime = 48;
        private const int Rkout = 24;
        private byte[] K;
        private byte[] iv;
        private const int PhaseDown = 1;
        private const int PhaseUp = 2;
        private const int NLANES = 12;
        private const int NROWS = 3;
        private const int NCOLUMS = 4;
        private const int MAXROUNDS = 12;
        private const int TAGLEN = 16;
        const int Rkin = 44;
        private byte[] tag;
        private readonly uint[] RC = {0x00000058, 0x00000038, 0x000003C0, 0x000000D0, 0x00000120, 0x00000014, 0x00000060,
        0x0000002C, 0x00000380, 0x000000F0, 0x000001A0, 0x00000012};
        private bool aadFinished;
        private bool encrypted;
        private bool initialised = false;
        public string AlgorithmName => "Xoodak AEAD";

        public IBlockCipher UnderlyingCipher => throw new NotImplementedException();

        private MemoryStream aadData = new MemoryStream();
        private MemoryStream message = new MemoryStream();

        enum MODE
        {
            ModeHash,
            ModeKeyed
        }

        public void Init(bool forEncryption, ICipherParameters param)
        {
            this.forEncryption = forEncryption;
            if (!(param is ParametersWithIV))
            {
                throw new ArgumentException("Xoodyak init parameters must include an IV");
            }
            ParametersWithIV ivParams = (ParametersWithIV)param;
            iv = ivParams.GetIV();
            if (iv == null || iv.Length != 16)
            {
                throw new ArgumentException("Xoodyak requires exactly 16 bytes of IV");
            }
            if (!(ivParams.Parameters is KeyParameter))
            {
                throw new ArgumentException("Xoodyak init parameters must include a key");
            }
            KeyParameter key = (KeyParameter)ivParams.Parameters;
            K = key.GetKey();
            if (K.Length != 16)
            {
                throw new ArgumentException("Xoodyak key must be 128 bits long");
            }
            state = new byte[48];
            tag = new byte[TAGLEN];
            initialised = true;
            reset(false);
        }

        public void ProcessAadByte(byte input)
        {
            if (aadFinished)
            {
                throw new ArgumentException("AAD cannot be added after reading a full block(" + GetBlockSize() +
                    " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
            }
            aadData.Write(new byte[] { input }, 0, 1);
        }


        public void ProcessAadBytes(byte[] input, int inOff, int len)
        {
            if (aadFinished)
            {
                throw new ArgumentException("AAD cannot be added after reading a full block(" + GetBlockSize() +
                    " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
            }
            if ((inOff + len) > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }
            aadData.Write(input, inOff, len);
        }


        public int ProcessByte(byte input, byte[] output, int outOff)
        {
            return ProcessBytes(new byte[] { input }, 0, 1, output, outOff);
        }

        private void processAAD()
        {
            if (!aadFinished)
            {
                byte[] ad = aadData.GetBuffer();
                AbsorbAny(ad, 0, (int)aadData.Length, Rabsorb, 0x03);
                aadFinished = true;
            }
        }

        public int ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            if (!initialised)
            {
                throw new ArgumentException("Need call init function before encryption/decryption");
            }
            if (mode != MODE.ModeKeyed)
            {
                throw new ArgumentException("Xoodyak has not been initialised");
            }
            if (inOff + len > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }
            message.Write(input, inOff, len);
            int blockLen = (int)message.Length - (forEncryption ? 0 : TAGLEN);
            if (blockLen >= GetBlockSize())
            {
                byte[] blocks = message.GetBuffer();
                len = blockLen / GetBlockSize() * GetBlockSize();
                if (len + outOff > output.Length)
                {
                    throw new OutputLengthException("output buffer is too short");
                }
                processAAD();
                encrypt(blocks, 0, len, output, outOff);
                int messageLen = (int)message.Length;
                message.SetLength(0);
                message.Write(blocks, len, messageLen - len);
                return len;
            }
            return 0;
        }

        private int encrypt(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            int IOLen = len;
            int splitLen;
            byte[] P = new byte[Rkout];
            uint Cu = encrypted ? 0u : 0x80u;
            while (IOLen != 0 || !encrypted)
            {
                splitLen = System.Math.Min(IOLen, Rkout); /* use Rkout instead of Rsqueeze, this function is only called in keyed mode */
                if (forEncryption)
                {
                    Array.Copy(input, inOff, P, 0, splitLen);
                }
                Up(null, 0, Cu); /* Up without extract */
                /* Extract from Up and Add */
                for (int i = 0; i < splitLen; i++)
                {
                    output[outOff + i] = (byte)(input[inOff++] ^ state[i]);
                }
                if (forEncryption)
                {
                    Down(P, 0, splitLen, 0x00);
                }
                else
                {
                    Down(output, outOff, splitLen, 0x00);
                }
                Cu = 0x00;
                outOff += splitLen;
                IOLen -= splitLen;
                encrypted = true;
            }
            return len;
        }


        public int DoFinal(byte[] output, int outOff)
        {
            if (!initialised)
            {
                throw new ArgumentException("Need call init function before encryption/decryption");
            }

            byte[] blocks = message.GetBuffer();
            int len = (int)message.Length;
            if ((forEncryption && len + TAGLEN + outOff > output.Length) ||
                (!forEncryption && len - TAGLEN + outOff > output.Length))
            {
                throw new OutputLengthException("output buffer too short");
            }
            processAAD();
            int rv = 0;
            if (forEncryption)
            {
                encrypt(blocks, 0, len, output, outOff);
                outOff += len;
                tag = new byte[TAGLEN];
                Up(tag, TAGLEN, 0x40);
                Array.Copy(tag, 0, output, outOff, TAGLEN);
                rv = len + TAGLEN;
            }
            else
            {
                int inOff = len - TAGLEN;
                rv = inOff;
                encrypt(blocks, 0, inOff, output, outOff);
                tag = new byte[TAGLEN];
                Up(tag, TAGLEN, 0x40);
                for (int i = 0; i < TAGLEN; ++i)
                {
                    if (tag[i] != blocks[inOff++])
                    {
                        throw new ArgumentException("Mac does not match");
                    }
                }
            }
            reset(false);
            return rv;
        }


        public byte[] GetMac()
        {
            return tag;
        }


        public int GetUpdateOutputSize(int len)
        {
            return len;
        }


        public int GetOutputSize(int len)
        {
            return len + TAGLEN;
        }


        public void Reset()
        {
            if (!initialised)
            {
                throw new ArgumentException("Need call init function before encryption/decryption");
            }
            reset(true);
        }

        private void reset(bool clearMac)
        {
            if (clearMac)
            {
                tag = null;
            }
            Arrays.Fill(state, (byte)0);
            aadFinished = false;
            encrypted = false;
            phase = PhaseUp;
            message.SetLength(0);
            aadData.SetLength(0);
            //Absorb key
            int KLen = K.Length;
            int IDLen = iv.Length;
            byte[] KID = new byte[Rkin];
            mode = MODE.ModeKeyed;
            Rabsorb = Rkin;
            Array.Copy(K, 0, KID, 0, KLen);
            Array.Copy(iv, 0, KID, KLen, IDLen);
            KID[KLen + IDLen] = (byte)IDLen;
            AbsorbAny(KID, 0, KLen + IDLen + 1, Rabsorb, 0x02);
        }

        private void AbsorbAny(byte[] X, int Xoff, int XLen, int r, uint Cd)
        {
            int splitLen;
            do
            {
                if (phase != PhaseUp)
                {
                    Up(null, 0, 0);
                }
                splitLen = System.Math.Min(XLen, r);
                Down(X, Xoff, splitLen, Cd);
                Cd = 0;
                Xoff += splitLen;
                XLen -= splitLen;
            }
            while (XLen != 0);
        }

        private void Up(byte[] Yi, int YiLen, uint Cu)
        {
            if (mode != MODE.ModeHash)
            {
                state[f_bPrime - 1] ^= (byte)Cu;
            }
            uint[] a = new uint[NLANES];
            Pack.LE_To_UInt32(state, 0, a, 0, a.Length);
            uint x, y;
            uint[] b = new uint[NLANES];
            uint[] p = new uint[NCOLUMS];
            uint[] e = new uint[NCOLUMS];
            for (int i = 0; i < MAXROUNDS; ++i)
            {
                /* Theta: Column Parity Mixer */
                for (x = 0; x < NCOLUMS; ++x)
                {
                    p[x] = a[index(x, 0)] ^ a[index(x, 1)] ^ a[index(x, 2)];
                }
                for (x = 0; x < NCOLUMS; ++x)
                {
                    y = p[(x + 3) & 3];
                    e[x] = ROTL32(y, 5) ^ ROTL32(y, 14);
                }
                for (x = 0; x < NCOLUMS; ++x)
                {
                    for (y = 0; y < NROWS; ++y)
                    {
                        a[index(x, y)] ^= e[x];
                    }
                }
                /* Rho-west: plane shift */
                for (x = 0; x < NCOLUMS; ++x)
                {
                    b[index(x, 0)] = a[index(x, 0)];
                    b[index(x, 1)] = a[index(x + 3, 1)];
                    b[index(x, 2)] = ROTL32(a[index(x, 2)], 11);
                }
                /* Iota: round ant */
                b[0] ^= RC[i];
                /* Chi: non linear layer */
                for (x = 0; x < NCOLUMS; ++x)
                {
                    for (y = 0; y < NROWS; ++y)
                    {
                        a[index(x, y)] = b[index(x, y)] ^ (~b[index(x, y + 1)] & b[index(x, y + 2)]);
                    }
                }
                /* Rho-east: plane shift */
                for (x = 0; x < NCOLUMS; ++x)
                {
                    b[index(x, 0)] = a[index(x, 0)];
                    b[index(x, 1)] = ROTL32(a[index(x, 1)], 1);
                    b[index(x, 2)] = ROTL32(a[index(x + 2, 2)], 8);
                }
                Array.Copy(b, 0, a, 0, NLANES);
            }
            Pack.UInt32_To_LE(a, 0, a.Length, state, 0);
            phase = PhaseUp;
            if (Yi != null)
            {
                Array.Copy(state, 0, Yi, 0, YiLen);
            }
        }

        void Down(byte[] Xi, int XiOff, int XiLen, uint Cd)
        {
            for (int i = 0; i < XiLen; i++)
            {
                state[i] ^= Xi[XiOff++];
            }
            state[XiLen] ^= 0x01;
            state[f_bPrime - 1] ^= (byte)((mode == MODE.ModeHash) ? (Cd & 0x01) : Cd);
            phase = PhaseDown;
        }

        private uint index(uint x, uint y)
        {
            return (((y % NROWS) * NCOLUMS) + ((x) % NCOLUMS));
        }

        private uint ROTL32(uint a, int offset)
        {
            return (a << (offset & 31)) ^ (a >> ((32 - (offset)) & 31));
        }

        public int GetBlockSize()
        {
            return Rkout;
        }

        public int GetKeyBytesSize()
        {
            return 16;
        }

        public int GetIVBytesSize()
        {
            return 16;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            aadData.Write(input);
        }

        public int ProcessByte(byte input, Span<byte> output)
        {
            byte[] rv = new byte[1];
            int len = ProcessBytes(new byte[] { input }, 0, 1, rv, 0);
            rv.AsSpan(0, len).CopyTo(output);
            return len;
        }

        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            byte[] rv = new byte[input.Length];
            int len = ProcessBytes(input.ToArray(), 0, rv.Length, rv, 0);
            rv.AsSpan(0, len).CopyTo(output);
            return len;
        }

        public int DoFinal(Span<byte> output)
        {
            byte[] rv;
            if (forEncryption)
            {
                rv = new byte[message.Length + 16];
            }
            else
            {
                rv = new byte[message.Length - 16];
            }
            int len = DoFinal(rv, 0);
            rv.AsSpan(0, len).CopyTo(output);
            return rv.Length;
        }

#endif

    }
}