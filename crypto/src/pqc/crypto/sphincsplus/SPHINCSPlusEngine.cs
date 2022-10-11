using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal abstract class SphincsPlusEngine
    {
        bool robust;

        internal int N;

        internal uint WOTS_W;
        internal int WOTS_LOGW;
        internal int WOTS_LEN;
        internal int WOTS_LEN1;
        internal int WOTS_LEN2;

        internal uint D;
        internal int A; // FORS_HEIGHT
        internal int K; // FORS_TREES
        uint FH; // FULL_HEIGHT
        internal uint H_PRIME; // H / D

        internal uint T; // T = 1 << A

        public SphincsPlusEngine(bool robust, int n, uint w, uint d, int a, int k, uint h)
        {
            this.N = n;

            /* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
            if (w == 16)
            {
                WOTS_LOGW = 4;
                WOTS_LEN1 = (8 * N / WOTS_LOGW);
                if (N <= 8)
                {
                    WOTS_LEN2 = 2;
                }
                else if (N <= 136)
                {
                    WOTS_LEN2 = 3;
                }
                else if (N <= 256)
                {
                    WOTS_LEN2 = 4;
                }
                else
                {
                    throw new ArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
                }
            }
            else if (w == 256)
            {
                WOTS_LOGW = 8;
                WOTS_LEN1 = (8 * N / WOTS_LOGW);
                if (N <= 1)
                {
                    WOTS_LEN2 = 1;
                }
                else if (N <= 256)
                {
                    WOTS_LEN2 = 2;
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

            this.WOTS_W = w;
            this.WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;

            this.robust = robust;
            this.D = d;
            this.A = a;
            this.K = k;
            this.FH = h;
            this.H_PRIME = (h / d);
            this.T = 1U << a;
        }

        public abstract void Init(byte[] pkSeed);

        public abstract byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1);

        public abstract byte[] H(byte[] pkSeed, Adrs adrs, byte[] m1, byte[] m2);

        public abstract IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message);

        public abstract byte[] T_l(byte[] pkSeed, Adrs adrs, byte[] m);

        public abstract void PRF(byte[] pkSeed, byte[] skSeed, Adrs adrs, byte[] prf, int prfOff);

        public abstract byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message);

        internal class Sha2Engine
            : SphincsPlusEngine
        {
            private HMac treeHMac;
            private Mgf1BytesGenerator mgf1;
            private byte[] hmacBuf;
            private IDigest msgDigest;
            private byte[] msgDigestBuf;
            private int bl;
            private IDigest sha256;
            private byte[] sha256Buf;

            private IMemoable msgMemo;
            private IMemoable sha256Memo;

            public Sha2Engine(bool robust, int n, uint w, uint d, int a, int k, uint h)
                : base(robust, n, w, d, a, k, h)
            {
                sha256 = new Sha256Digest();
                sha256Buf = new byte[sha256.GetDigestSize()];

                if (n == 16)
                {
                    this.msgDigest = new Sha256Digest();
                    this.treeHMac = new HMac(new Sha256Digest());
                    this.mgf1 = new Mgf1BytesGenerator(new Sha256Digest());
                    this.bl = 64;
                }
                else
                {
                    this.msgDigest = new Sha512Digest();
                    this.treeHMac = new HMac(new Sha512Digest());
                    this.mgf1 = new Mgf1BytesGenerator(new Sha512Digest());
                    this.bl = 128;
                }

                this.hmacBuf = new byte[treeHMac.GetMacSize()];
                this.msgDigestBuf = new byte[msgDigest.GetDigestSize()];
            }

            public override void Init(byte[] pkSeed)
            {
                byte[] padding = new byte[bl];

                msgDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                msgDigest.BlockUpdate(padding, 0, bl - N);
                msgMemo = ((IMemoable)msgDigest).Copy();
                msgDigest.Reset();

                sha256.BlockUpdate(pkSeed, 0, pkSeed.Length);
                sha256.BlockUpdate(padding, 0, 64 - N);
                sha256Memo = ((IMemoable)sha256).Copy();
                sha256.Reset();
            }

            public override byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1)
            {
                byte[] compressedAdrs = CompressedAdrs(adrs);

                if (robust)
                {
                    m1 = Bitmask256(Arrays.Concatenate(pkSeed, compressedAdrs), m1);
                }

                ((IMemoable)sha256).Reset(sha256Memo);

                sha256.BlockUpdate(compressedAdrs, 0, compressedAdrs.Length);
                sha256.BlockUpdate(m1, 0, m1.Length);
                sha256.DoFinal(sha256Buf, 0);

                return Arrays.CopyOfRange(sha256Buf, 0, N);
            }

            public override byte[] H(byte[] pkSeed, Adrs adrs, byte[] m1, byte[] m2)
            {
                byte[] compressedAdrs = CompressedAdrs(adrs);

                ((IMemoable)msgDigest).Reset(msgMemo);

                msgDigest.BlockUpdate(compressedAdrs, 0, compressedAdrs.Length);
                if (robust)
                {
                    byte[] m1m2 = Bitmask(Arrays.Concatenate(pkSeed, compressedAdrs), m1, m2);
                    msgDigest.BlockUpdate(m1m2, 0, m1m2.Length);
                }
                else
                {
                    msgDigest.BlockUpdate(m1, 0, m1.Length);
                    msgDigest.BlockUpdate(m2, 0, m2.Length);
                }

                msgDigest.DoFinal(msgDigestBuf, 0);

                return Arrays.CopyOfRange(msgDigestBuf, 0, N);
            }

            public override IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message)
            {
                int forsMsgBytes = (((A * K) + 7) / 8);
                uint leafBits = FH / D;
                uint treeBits = FH - leafBits;
                uint leafBytes = (leafBits + 7) / 8;
                uint treeBytes = (treeBits + 7) / 8;
                uint m = (uint)forsMsgBytes + treeBytes + leafBytes;

                byte[] dig = new byte[msgDigest.GetDigestSize()];
                msgDigest.BlockUpdate(prf, 0, prf.Length);
                msgDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                msgDigest.BlockUpdate(pkRoot, 0, pkRoot.Length);
                msgDigest.BlockUpdate(message, 0, message.Length);
                msgDigest.DoFinal(dig, 0);

                byte[] output = new byte[m];
                output = Bitmask(Arrays.ConcatenateAll(prf, pkSeed, dig), output);

                // tree index
                // currently, only indexes up to 64 bits are supported
                ulong treeIndex = Pack.BE_To_UInt64_Partial(output, forsMsgBytes, (int)treeBytes)
                                & ulong.MaxValue >> (64 - (int)treeBits);

                uint leafIndex = Pack.BE_To_UInt32_Partial(output, forsMsgBytes + (int)treeBytes, (int)leafBytes)
                               & uint.MaxValue >> (32 - (int)leafBits);

                return new IndexedDigest(treeIndex, leafIndex, Arrays.CopyOfRange(output, 0, forsMsgBytes));
            }

            public override byte[] T_l(byte[] pkSeed, Adrs adrs, byte[] m)
            {
                byte[] compressedAdrs = CompressedAdrs(adrs);
                if (robust)
                {
                    m = Bitmask(Arrays.Concatenate(pkSeed, compressedAdrs), m);
                }


                ((IMemoable)msgDigest).Reset(msgMemo);

                msgDigest.BlockUpdate(compressedAdrs, 0, compressedAdrs.Length);
                msgDigest.BlockUpdate(m, 0, m.Length);
                msgDigest.DoFinal(msgDigestBuf, 0);

                return Arrays.CopyOfRange(msgDigestBuf, 0, N);
            }

            public override void PRF(byte[] pkSeed, byte[] skSeed, Adrs adrs, byte[] prf, int prfOff)
            {
                int n = skSeed.Length;

                ((IMemoable)sha256).Reset(sha256Memo);

                byte[] compressedAdrs = CompressedAdrs(adrs);

                sha256.BlockUpdate(compressedAdrs, 0, compressedAdrs.Length);
                sha256.BlockUpdate(skSeed, 0, skSeed.Length);
                sha256.DoFinal(sha256Buf, 0);

                Array.Copy(sha256Buf, 0, prf, prfOff, n);
            }

            public override byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message)
            {
                treeHMac.Init(new KeyParameter(prf));
                treeHMac.BlockUpdate(randomiser, 0, randomiser.Length);
                treeHMac.BlockUpdate(message, 0, message.Length);
                treeHMac.DoFinal(hmacBuf, 0);

                return Arrays.CopyOfRange(hmacBuf, 0, N);
            }

            private byte[] CompressedAdrs(Adrs adrs)
            {
                byte[] rv = new byte[22];
                Array.Copy(adrs.value, Adrs.OFFSET_LAYER + 3, rv, 0, 1); // LSB layer address
                Array.Copy(adrs.value, Adrs.OFFSET_TREE + 4, rv, 1, 8); // LS 8 bytes Tree address
                Array.Copy(adrs.value, Adrs.OFFSET_TYPE + 3, rv, 9, 1); // LSB type
                Array.Copy(adrs.value, 20, rv, 10, 12);

                return rv;
            }

            protected byte[] Bitmask(byte[] key, byte[] m)
            {
                byte[] mask = new byte[m.Length];

                mgf1.Init(new MgfParameters(key));

                mgf1.GenerateBytes(mask, 0, mask.Length);

                for (int i = 0; i < m.Length; ++i)
                {
                    mask[i] ^= m[i];
                }

                return mask;
            }


            protected byte[] Bitmask(byte[] key, byte[] m1, byte[] m2)
            {
                byte[] mask = new byte[m1.Length + m2.Length];

                mgf1.Init(new MgfParameters(key));

                mgf1.GenerateBytes(mask, 0, mask.Length);

                for (int i = 0; i < m1.Length; ++i)
                {
                    mask[i] ^= m1[i];
                }
                for (int i = 0; i < m2.Length; ++i)
                {
                    mask[i + m1.Length] ^= m2[i];
                }


                return mask;
            }

            protected byte[] Bitmask256(byte[] key, byte[] m)
            {
                byte[] mask = new byte[m.Length];

                Mgf1BytesGenerator mgf1 = new Mgf1BytesGenerator(new Sha256Digest());

                mgf1.Init(new MgfParameters(key));

                mgf1.GenerateBytes(mask, 0, mask.Length);

                for (int i = 0; i < m.Length; ++i)
                {
                    mask[i] ^= m[i];
                }

                return mask;
            }
        }

        internal class Shake256Engine
            : SphincsPlusEngine
        {
            private IXof treeDigest;
            private IXof maskDigest;

            public Shake256Engine(bool robust, int n, uint w, uint d, int a, int k, uint h)
                : base(robust, n, w, d, a, k, h)
            {
                this.treeDigest = new ShakeDigest(256);
                this.maskDigest = new ShakeDigest(256);
            }

            public override void Init(byte[] pkSeed)
            {
                // TODO: add use of memo
            }

            public override byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1)
            {
                byte[] mTheta = m1;
                if (robust)
                {
                    mTheta = Bitmask(pkSeed, adrs, m1);
                }

                byte[] rv = new byte[N];

                treeDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                treeDigest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                treeDigest.BlockUpdate(mTheta, 0, mTheta.Length);
                treeDigest.OutputFinal(rv, 0, rv.Length);

                return rv;
            }

            public override byte[] H(byte[] pkSeed, Adrs adrs, byte[] m1, byte[] m2)
            {
                byte[] rv = new byte[N];
                treeDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                treeDigest.BlockUpdate(adrs.value, 0, adrs.value.Length);

                if (robust)
                {
                    byte[] m1m2 = Bitmask(pkSeed, adrs, m1, m2);

                    treeDigest.BlockUpdate(m1m2, 0, m1m2.Length);
                }
                else
                {
                    treeDigest.BlockUpdate(m1, 0, m1.Length);
                    treeDigest.BlockUpdate(m2, 0, m2.Length);
                }

                treeDigest.OutputFinal(rv, 0, rv.Length);

                return rv;
            }

            public override IndexedDigest H_msg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] message)
            {
                int forsMsgBytes = ((A * K) + 7) / 8;
                uint leafBits = FH / D;
                uint treeBits = FH - leafBits;
                uint leafBytes = (leafBits + 7) / 8;
                uint treeBytes = (treeBits + 7) / 8;
                uint m = (uint)(forsMsgBytes + treeBytes + leafBytes);
                byte[] output = new byte[m];

                treeDigest.BlockUpdate(R, 0, R.Length);
                treeDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                treeDigest.BlockUpdate(pkRoot, 0, pkRoot.Length);
                treeDigest.BlockUpdate(message, 0, message.Length);
                treeDigest.OutputFinal(output, 0, output.Length);

                // tree index
                // currently, only indexes up to 64 bits are supported
                ulong treeIndex = Pack.BE_To_UInt64_Partial(output, forsMsgBytes, (int)treeBytes)
                                & ulong.MaxValue >> (64 - (int)treeBits);

                uint leafIndex = Pack.BE_To_UInt32_Partial(output, forsMsgBytes + (int)treeBytes, (int)leafBytes)
                               & uint.MaxValue >> (32 - (int)leafBits);

                return new IndexedDigest(treeIndex, leafIndex, Arrays.CopyOfRange(output, 0, forsMsgBytes));
            }

            public override byte[] T_l(byte[] pkSeed, Adrs adrs, byte[] m)
            {
                byte[] mTheta = m;
                if (robust)
                {
                    mTheta = Bitmask(pkSeed, adrs, m);
                }

                byte[] rv = new byte[N];

                treeDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                treeDigest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                treeDigest.BlockUpdate(mTheta, 0, mTheta.Length);
                treeDigest.OutputFinal(rv, 0, rv.Length);

                return rv;
            }

            public override void PRF(byte[] pkSeed, byte[] skSeed, Adrs adrs, byte[] prf, int prfOff)
            {
                treeDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                treeDigest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                treeDigest.BlockUpdate(skSeed, 0, skSeed.Length);
                treeDigest.OutputFinal(prf, prfOff, N);
            }

            public override byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message)
            {
                treeDigest.BlockUpdate(prf, 0, prf.Length);
                treeDigest.BlockUpdate(randomiser, 0, randomiser.Length);
                treeDigest.BlockUpdate(message, 0, message.Length);
                byte[] output = new byte[N];
                treeDigest.OutputFinal(output, 0, output.Length);
                return output;
            }

            protected byte[] Bitmask(byte[] pkSeed, Adrs adrs, byte[] m)
            {
                byte[] mask = new byte[m.Length];

                maskDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                maskDigest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                maskDigest.OutputFinal(mask, 0, mask.Length);

                for (int i = 0; i < m.Length; ++i)
                {
                    mask[i] ^= m[i];
                }

                return mask;
            }

            protected byte[] Bitmask(byte[] pkSeed, Adrs adrs, byte[] m1, byte[] m2)
            {
                byte[] mask = new byte[m1.Length + m2.Length];

                maskDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                maskDigest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                maskDigest.OutputFinal(mask, 0, mask.Length);

                for (int i = 0; i < m1.Length; ++i)
                {
                    mask[i] ^= m1[i];
                }
                for (int i = 0; i < m2.Length; ++i)
                {
                    mask[i + m1.Length] ^= m2[i];
                }

                return mask;
            }

        }

        internal class HarakaSEngine
            : SphincsPlusEngine
        {
            public HarakaSXof harakaSXof;
            public HarakaS256Digest harakaS256Digest;
            public HarakaS512Digest harakaS512Digest;

            public HarakaSEngine(bool robust, int n, uint w, uint d, int a, int k, uint h)
                : base(robust, n, w, d, a, k, h)
            {

            }

            public override void Init(byte[] pkSeed)
            {
                harakaSXof = new HarakaSXof(pkSeed);
                harakaS256Digest = new HarakaS256Digest(harakaSXof);
                harakaS512Digest = new HarakaS512Digest(harakaSXof);
            }

            public override byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1)
            {
                byte[] hash = new byte[32];
                harakaS512Digest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                if (robust)
                {
                    harakaS256Digest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                    harakaS256Digest.DoFinal(hash, 0);
                    for (int i = 0; i < m1.Length; ++i)
                    {
                        hash[i] ^= m1[i];
                    }
                    harakaS512Digest.BlockUpdate(hash, 0, m1.Length);
                }
                else
                {
                    harakaS512Digest.BlockUpdate(m1, 0, m1.Length);
                }
                // NOTE The digest implementation implicitly pads the input with zeros up to 64 length
                harakaS512Digest.DoFinal(hash, 0);
                return N == 32 ? hash : Arrays.CopyOfRange(hash, 0, N);
            }

            public override byte[] H(byte[] pkSeed, Adrs adrs, byte[] m1, byte[] m2)
            {
                byte[] rv = new byte[N];
                byte[] m = new byte[m1.Length + m2.Length];
                Array.Copy(m1, 0, m, 0, m1.Length);
                Array.Copy(m2, 0, m, m1.Length, m2.Length);
                m = Bitmask(adrs, m);
                harakaSXof.BlockUpdate(adrs.value, 0, adrs.value.Length);
                harakaSXof.BlockUpdate(m, 0, m.Length);
                harakaSXof.OutputFinal(rv, 0, rv.Length);
                return rv;
            }

            public override IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message)
            {
                int forsMsgBytes = ((A * K) + 7) >> 3;
                uint leafBits = FH / D;
                uint treeBits = FH - leafBits;
                uint leafBytes = (leafBits + 7) >> 3;
                uint treeBytes = (treeBits + 7) >> 3;

                byte[] output = new byte[forsMsgBytes + treeBytes + leafBytes];
                harakaSXof.BlockUpdate(prf, 0, prf.Length);
                harakaSXof.BlockUpdate(pkRoot, 0, pkRoot.Length);
                harakaSXof.BlockUpdate(message, 0, message.Length);
                harakaSXof.OutputFinal(output, 0, output.Length);

                // tree index
                // currently, only indexes up to 64 bits are supported
                ulong treeIndex = Pack.BE_To_UInt64_Partial(output, forsMsgBytes, (int)treeBytes)
                                & ulong.MaxValue >> (64 - (int)treeBits);

                uint leafIndex = Pack.BE_To_UInt32_Partial(output, forsMsgBytes + (int)treeBytes, (int)leafBytes)
                               & uint.MaxValue >> (32 - (int)leafBits);

                return new IndexedDigest(treeIndex, leafIndex, Arrays.CopyOfRange(output, 0, forsMsgBytes));
            }

            public override byte[] T_l(byte[] pkSeed, Adrs adrs, byte[] m)
            {
                byte[] rv = new byte[N];
                m = Bitmask(adrs, m);
                harakaSXof.BlockUpdate(adrs.value, 0, adrs.value.Length);
                harakaSXof.BlockUpdate(m, 0, m.Length);
                harakaSXof.OutputFinal(rv, 0, rv.Length);
                return rv;
            }

            public override void PRF(byte[] pkSeed, byte[] skSeed, Adrs adrs, byte[] prf, int prfOff)
            {
                byte[] rv = new byte[32];
                harakaS512Digest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                harakaS512Digest.BlockUpdate(skSeed, 0, skSeed.Length);
                harakaS512Digest.DoFinal(rv, 0);
                Array.Copy(rv, 0, prf, prfOff, N);
            }

            public override byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message)
            {
                byte[] rv = new byte[N];
                harakaSXof.BlockUpdate(prf, 0, prf.Length);
                harakaSXof.BlockUpdate(randomiser, 0, randomiser.Length);
                harakaSXof.BlockUpdate(message, 0, message.Length);
                harakaSXof.OutputFinal(rv, 0, rv.Length);
                return rv;
            }

            protected byte[] Bitmask(Adrs adrs, byte[] m)
            {
                if (robust)
                {
                    byte[] mask = new byte[m.Length];
                    harakaSXof.BlockUpdate(adrs.value, 0, adrs.value.Length);
                    harakaSXof.OutputFinal(mask, 0, mask.Length);
                    for (int i = 0; i < m.Length; ++i)
                    {
                        m[i] ^= mask[i];
                    }
                }
                return m;
            }
        }

#if NETCOREAPP3_0_OR_GREATER
        internal class HarakaSEngine_X86
            : SphincsPlusEngine
        {
            public static bool IsSupported => Haraka256_X86.IsSupported && Haraka512_X86.IsSupported
                && HarakaS_X86.IsSupported;

            private HarakaS_X86 m_harakaS;

            public HarakaSEngine_X86(bool robust, int n, uint w, uint d, int a, int k, uint h)
                : base(robust, n, w, d, a, k, h)
            {
            }

            public override void Init(byte[] pkSeed)
            {
                m_harakaS = new HarakaS_X86(pkSeed);
            }

            public override byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1)
            {
                Span<byte> buf = stackalloc byte[64];
                adrs.value.CopyTo(buf);

                if (robust)
                {
                    Span<byte> mask = stackalloc byte[32];
                    Haraka256_X86.Hash(adrs.value, mask, m_harakaS.RoundConstants);
                    for (int i = 0; i < m1.Length; ++i)
                    {
                        buf[32 + i] = (byte)(m1[i] ^ mask[i]);
                    }
                }
                else
                {
                    m1.CopyTo(buf[32..]);
                }
                Haraka512_X86.Hash(buf, buf, m_harakaS.RoundConstants);
                return buf[..N].ToArray();
            }

            public override byte[] H(byte[] pkSeed, Adrs adrs, byte[] m1, byte[] m2)
            {
                Span<byte> m = stackalloc byte[m1.Length + m2.Length];
                m1.CopyTo(m);
                m2.CopyTo(m[m1.Length..]);
                Bitmask(adrs, m);

                byte[] rv = new byte[N];
                m_harakaS.BlockUpdate(adrs.value);
                m_harakaS.BlockUpdate(m);
                m_harakaS.OutputFinal(rv);
                return rv;
            }

            public override IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message)
            {
                int forsMsgBytes = ((A * K) + 7) >> 3;
                int leafBits = (int)(FH / D);
                int treeBits = (int)FH - leafBits;
                int leafBytes = (leafBits + 7) >> 3;
                int treeBytes = (treeBits + 7) >> 3;

                byte[] output = new byte[forsMsgBytes];
                Span<byte> indices = stackalloc byte[treeBytes + leafBytes];

                m_harakaS.BlockUpdate(prf);
                m_harakaS.BlockUpdate(pkRoot);
                m_harakaS.BlockUpdate(message);
                m_harakaS.Output(output);
                m_harakaS.OutputFinal(indices);

                // tree index
                // currently, only indexes up to 64 bits are supported
                ulong treeIndex = Pack.BE_To_UInt64_Partial(indices[..treeBytes])
                                & ulong.MaxValue >> (64 - treeBits);

                uint leafIndex = Pack.BE_To_UInt32_Partial(indices[treeBytes..])
                               & uint.MaxValue >> (32 - leafBits);

                return new IndexedDigest(treeIndex, leafIndex, output);
            }

            public override byte[] T_l(byte[] pkSeed, Adrs adrs, byte[] m)
            {
                Bitmask(adrs, m);

                byte[] rv = new byte[N];
                m_harakaS.BlockUpdate(adrs.value);
                m_harakaS.BlockUpdate(m);
                m_harakaS.OutputFinal(rv);
                return rv;
            }

            public override void PRF(byte[] pkSeed, byte[] skSeed, Adrs adrs, byte[] prf, int prfOff)
            {
                Span<byte> buf = stackalloc byte[64];
                adrs.value.CopyTo(buf);
                skSeed.CopyTo(buf[32..]);
                Haraka512_X86.Hash(buf, buf, m_harakaS.RoundConstants);
                buf[..N].CopyTo(prf.AsSpan(prfOff));
            }

            public override byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message)
            {
                byte[] rv = new byte[N];
                m_harakaS.BlockUpdate(prf);
                m_harakaS.BlockUpdate(randomiser);
                m_harakaS.BlockUpdate(message);
                m_harakaS.OutputFinal(rv);
                return rv;
            }

            protected void Bitmask(Adrs adrs, Span<byte> m)
            {
                if (robust)
                {
                    Span<byte> mask = stackalloc byte[m.Length];
                    m_harakaS.BlockUpdate(adrs.value);
                    m_harakaS.OutputFinal(mask);
                    for (int i = 0; i < m.Length; ++i)
                    {
                        m[i] ^= mask[i];
                    }
                }
            }
        }
#endif
    }
}
