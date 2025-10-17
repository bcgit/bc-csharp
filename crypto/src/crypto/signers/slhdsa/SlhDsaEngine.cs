using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal abstract class SlhDsaEngine
    {
        private static readonly byte[] Zeros = new byte[128];

        internal readonly int N;

        internal readonly int WotsW;
        internal readonly int WotsLogW;
        internal readonly int WotsLen;
        internal readonly int WotsLen1;
        internal readonly int WotsLen2;

        internal readonly int D;
        internal readonly int A; // FORS_HEIGHT
        internal readonly int K; // FORS_TREES
        internal readonly int FH; // FULL_HEIGHT
        internal readonly int HPrime; // H / D

        internal readonly int SignatureLength;

        internal SlhDsaEngine(int n, int w, int d, int a, int k, int h)
        {
            this.N = n;

            /* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
            if (w == 16)
            {
                WotsLogW = 4;
                WotsLen1 = (8 * N / WotsLogW);
                if (N <= 8)
                {
                    WotsLen2 = 2;
                }
                else if (N <= 136)
                {
                    WotsLen2 = 3;
                }
                else if (N <= 256)
                {
                    WotsLen2 = 4;
                }
                else
                {
                    throw new ArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
                }
            }
            else if (w == 256)
            {
                WotsLogW = 8;
                WotsLen1 = (8 * N / WotsLogW);
                if (N <= 1)
                {
                    WotsLen2 = 1;
                }
                else if (N <= 256)
                {
                    WotsLen2 = 2;
                }
                else
                {
                    throw new ArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
                }
            }
            else
            {
                throw new ArgumentException("wots_w assumed 16 or 256");
            }

            this.WotsW = w;
            this.WotsLen = WotsLen1 + WotsLen2;

            this.D = d;
            this.A = a;
            this.K = k;
            this.FH = h;
            this.HPrime = (h / d);

            this.SignatureLength = (1 + K * (1 + A) + FH + D * WotsLen) * N;
        }

        public abstract void Init(byte[] pkSeed);

        public abstract void F(Adrs adrs, byte[] m1, int m1Off);

        public abstract void H(Adrs adrs, byte[] m1, int m1Off, byte[] m2, int m2Off, byte[] output);

        public abstract IndexedDigest HMsg(byte[] prf, int prfOff, byte[] pkSeed, byte[] pkRoot, byte[] msg,
            int msgOff, int msgLen);

        public abstract void T_l(Adrs adrs, byte[] m, byte[] output, int outputOff);

        public abstract void Prf(Adrs adrs, byte[] skSeed, byte[] prf, int prfOff);

        public abstract void PrfMsg(byte[] prf, byte[] randomiser, byte[] msg, int msgOff, int msgLen, byte[] r,
            int rOff);

        internal sealed class Sha2Engine
            : SlhDsaEngine
        {
            private HMac treeHMac;
            private Mgf1BytesGenerator mgf1;
            private byte[] hmacBuf;
            private IDigest msgDigest;
            private byte[] msgDigestBuf;
            private IDigest sha256;
            private byte[] sha256Buf;

            private IMemoable msgMemo;
            private IMemoable sha256Memo;

            public Sha2Engine(int n, int w, int d, int a, int k, int h)
                : base(n, w, d, a, k, h)
            {
                sha256 = new Sha256Digest();
                sha256Buf = new byte[sha256.GetDigestSize()];

                if (n == 16)
                {
                    this.msgDigest = new Sha256Digest();
                    this.treeHMac = new HMac(new Sha256Digest());
                    this.mgf1 = new Mgf1BytesGenerator(new Sha256Digest());
                }
                else
                {
                    this.msgDigest = new Sha512Digest();
                    this.treeHMac = new HMac(new Sha512Digest());
                    this.mgf1 = new Mgf1BytesGenerator(new Sha512Digest());
                }

                this.hmacBuf = new byte[treeHMac.GetMacSize()];
                this.msgDigestBuf = new byte[msgDigest.GetDigestSize()];
            }

            public override void Init(byte[] pkSeed)
            {
                int n = N;
                int bl = n == 16 ? 64 : 128;

                msgDigest.BlockUpdate(pkSeed, 0, n);
                msgDigest.BlockUpdate(Zeros, 0, bl - n);
                msgMemo = ((IMemoable)msgDigest).Copy();
                msgDigest.Reset();

                sha256.BlockUpdate(pkSeed, 0, n);
                sha256.BlockUpdate(Zeros, 0, 64 - n);
                sha256Memo = ((IMemoable)sha256).Copy();
                sha256.Reset();
            }

            public override void F(Adrs adrs, byte[] m1, int m1Off)
            {
                byte[] compressedAdrs = CompressedAdrs(adrs);

                ((IMemoable)sha256).Reset(sha256Memo);

                sha256.BlockUpdate(compressedAdrs, 0, compressedAdrs.Length);
                sha256.BlockUpdate(m1, m1Off, N);
                sha256.DoFinal(sha256Buf, 0);

                Array.Copy(sha256Buf, 0, m1, m1Off, N);
            }

            public override void H(Adrs adrs, byte[] m1, int m1Off, byte[] m2, int m2Off, byte[] output)
            {
                byte[] compressedAdrs = CompressedAdrs(adrs);

                ((IMemoable)msgDigest).Reset(msgMemo);

                msgDigest.BlockUpdate(compressedAdrs, 0, compressedAdrs.Length);
                msgDigest.BlockUpdate(m1, m1Off, N);
                msgDigest.BlockUpdate(m2, m2Off, N);
                msgDigest.DoFinal(msgDigestBuf, 0);

                Array.Copy(msgDigestBuf, 0, output, 0, N);
            }

            public override IndexedDigest HMsg(byte[] prf, int prfOff, byte[] pkSeed, byte[] pkRoot, byte[] msg,
                int msgOff, int msgLen)
            {
                int forsMsgBytes = ((A * K) + 7) / 8;
                int leafBits = FH / D;
                int treeBits = FH - leafBits;
                int leafBytes = (leafBits + 7) / 8;
                int treeBytes = (treeBits + 7) / 8;
                int m = forsMsgBytes + treeBytes + leafBytes;
                byte[] output = new byte[m];

                // MGF1
                {
                    byte[] dig = new byte[msgDigest.GetDigestSize()];
                    msgDigest.BlockUpdate(prf, prfOff, N);
                    msgDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                    msgDigest.BlockUpdate(pkRoot, 0, pkRoot.Length);
                    msgDigest.BlockUpdate(msg, msgOff, msgLen);
                    msgDigest.DoFinal(dig, 0);

                    byte[] key = new byte[N + pkSeed.Length + dig.Length];
                    Array.Copy(prf, prfOff, key, 0, N);
                    Array.Copy(pkSeed, 0, key, N, pkSeed.Length);
                    Array.Copy(dig, 0, key, N + pkSeed.Length, dig.Length);

                    mgf1.Init(new MgfParameters(key));
                    mgf1.GenerateBytes(output, 0, m);
                }

                // tree index; currently, only indexes up to 64 bits are supported
                ulong treeIndex = Pack.BE_To_UInt64_Low(output, forsMsgBytes, treeBytes)
                                & ulong.MaxValue >> (64 - treeBits);

                uint leafIndex = Pack.BE_To_UInt32_Low(output, forsMsgBytes + treeBytes, leafBytes)
                               & uint.MaxValue >> (32 - leafBits);

                return new IndexedDigest(treeIndex, leafIndex, Arrays.CopyOfRange(output, 0, forsMsgBytes));
            }

            public override void T_l(Adrs adrs, byte[] m, byte[] output, int outputOff)
            {
                ((IMemoable)msgDigest).Reset(msgMemo);

                byte[] compressedAdrs = CompressedAdrs(adrs);

                msgDigest.BlockUpdate(compressedAdrs, 0, compressedAdrs.Length);
                msgDigest.BlockUpdate(m, 0, m.Length);
                msgDigest.DoFinal(msgDigestBuf, 0);

                Array.Copy(msgDigestBuf, 0, output, outputOff, N);
            }

            public override void Prf(Adrs adrs, byte[] skSeed, byte[] prf, int prfOff)
            {
                ((IMemoable)sha256).Reset(sha256Memo);

                byte[] compressedAdrs = CompressedAdrs(adrs);

                sha256.BlockUpdate(compressedAdrs, 0, compressedAdrs.Length);
                sha256.BlockUpdate(skSeed, 0, N);
                sha256.DoFinal(sha256Buf, 0);

                Array.Copy(sha256Buf, 0, prf, prfOff, N);
            }

            public override void PrfMsg(byte[] prf, byte[] randomiser, byte[] msg, int msgOff, int msgLen, byte[] r,
                int rOff)
            {
                treeHMac.Init(new KeyParameter(prf));
                treeHMac.BlockUpdate(randomiser, 0, randomiser.Length);
                treeHMac.BlockUpdate(msg, msgOff, msgLen);
                treeHMac.DoFinal(hmacBuf, 0);

                Array.Copy(hmacBuf, 0, r, rOff, N);
            }

            private byte[] CompressedAdrs(Adrs adrs)
            {
                byte[] rv = new byte[22];
                Array.Copy(adrs.Value, Adrs.OffsetLayer + 3, rv, 0, 1); // LSB layer address
                Array.Copy(adrs.Value, Adrs.OffsetTree + 4, rv, 1, 8); // LS 8 bytes Tree address
                Array.Copy(adrs.Value, Adrs.OffsetType + 3, rv, 9, 1); // LSB type
                Array.Copy(adrs.Value, 20, rv, 10, 12);
                return rv;
            }
        }

        internal sealed class Shake256Engine
            : SlhDsaEngine
        {
            private readonly IXof m_treeDigest;
            private readonly byte[] m_pkSeed;

            public Shake256Engine(int n, int w, int d, int a, int k, int h)
                : base(n, w, d, a, k, h)
            {
                m_treeDigest = new ShakeDigest(256);
                m_pkSeed = new byte[n];
            }

            public override void Init(byte[] pkSeed)
            {
                Array.Copy(pkSeed, 0, m_pkSeed, 0, N);
            }

            public override void F(Adrs adrs, byte[] m1, int m1Off)
            {
                m_treeDigest.BlockUpdate(m_pkSeed, 0, N);
                m_treeDigest.BlockUpdate(adrs.Value, 0, adrs.Value.Length);
                m_treeDigest.BlockUpdate(m1, m1Off, N);
                m_treeDigest.OutputFinal(m1, m1Off, N);
            }

            public override void H(Adrs adrs, byte[] m1, int m1Off, byte[] m2, int m2Off, byte[] output)
            {
                m_treeDigest.BlockUpdate(m_pkSeed, 0, N);
                m_treeDigest.BlockUpdate(adrs.Value, 0, adrs.Value.Length);
                m_treeDigest.BlockUpdate(m1, m1Off, N);
                m_treeDigest.BlockUpdate(m2, m2Off, N);
                m_treeDigest.OutputFinal(output, 0, N);
            }

            public override IndexedDigest HMsg(byte[] prf, int prfOff, byte[] pkSeed, byte[] pkRoot, byte[] msg,
                int msgOff, int msgLen)
            {
                int forsMsgBytes = ((A * K) + 7) / 8;
                int leafBits = FH / D;
                int treeBits = FH - leafBits;
                int leafBytes = (leafBits + 7) / 8;
                int treeBytes = (treeBits + 7) / 8;
                int m = forsMsgBytes + treeBytes + leafBytes;
                byte[] output = new byte[m];

                m_treeDigest.BlockUpdate(prf, prfOff, N);
                m_treeDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                m_treeDigest.BlockUpdate(pkRoot, 0, pkRoot.Length);
                m_treeDigest.BlockUpdate(msg, msgOff, msgLen);
                m_treeDigest.OutputFinal(output, 0, output.Length);

                // tree index
                // currently, only indexes up to 64 bits are supported
                ulong treeIndex = Pack.BE_To_UInt64_Low(output, forsMsgBytes, treeBytes)
                                & ulong.MaxValue >> (64 - treeBits);

                uint leafIndex = Pack.BE_To_UInt32_Low(output, forsMsgBytes + treeBytes, leafBytes)
                               & uint.MaxValue >> (32 - leafBits);

                return new IndexedDigest(treeIndex, leafIndex, Arrays.CopyOfRange(output, 0, forsMsgBytes));
            }

            public override void T_l(Adrs adrs, byte[] m, byte[] output, int outputOff)
            {
                m_treeDigest.BlockUpdate(m_pkSeed, 0, N);
                m_treeDigest.BlockUpdate(adrs.Value, 0, adrs.Value.Length);
                m_treeDigest.BlockUpdate(m, 0, m.Length);
                m_treeDigest.OutputFinal(output, outputOff, N);
            }

            public override void Prf(Adrs adrs, byte[] skSeed, byte[] prf, int prfOff)
            {
                m_treeDigest.BlockUpdate(m_pkSeed, 0, N);
                m_treeDigest.BlockUpdate(adrs.Value, 0, adrs.Value.Length);
                m_treeDigest.BlockUpdate(skSeed, 0, skSeed.Length);
                m_treeDigest.OutputFinal(prf, prfOff, N);
            }

            public override void PrfMsg(byte[] prf, byte[] randomiser, byte[] msg, int msgOff, int msgLen, byte[] r,
                int rOff)
            {
                m_treeDigest.BlockUpdate(prf, 0, prf.Length);
                m_treeDigest.BlockUpdate(randomiser, 0, randomiser.Length);
                m_treeDigest.BlockUpdate(msg, msgOff, msgLen);
                m_treeDigest.OutputFinal(r, rOff, N);
            }
        }
    }
}
