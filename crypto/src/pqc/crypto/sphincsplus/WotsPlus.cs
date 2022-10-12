using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal class WotsPlus
    {
        private SphincsPlusEngine engine;
        private uint w;

        internal WotsPlus(SphincsPlusEngine engine)
        {
            this.engine = engine;
            this.w = this.engine.WOTS_W;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void PKGen(byte[] skSeed, byte[] pkSeed, Adrs paramAdrs, Span<byte> output)
#else
        internal void PKGen(byte[] skSeed, byte[] pkSeed, Adrs paramAdrs, byte[] output)
#endif
        {
            Adrs wotspkAdrs = new Adrs(paramAdrs); // copy address to create OTS public key address

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            byte[] tmpConcat = new byte[engine.WOTS_LEN * engine.N];
#else
            byte[][] tmp = new byte[engine.WOTS_LEN][];
            byte[] sk = new byte[engine.N];
#endif
            for (uint i = 0; i < engine.WOTS_LEN; i++)
            {
                Adrs adrs = new Adrs(paramAdrs);
                adrs.SetAdrsType(Adrs.WOTS_PRF);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress(i);
                adrs.SetHashAddress(0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                engine.PRF(pkSeed, skSeed, adrs, tmpConcat, engine.N * (int)i);
#else
                engine.PRF(pkSeed, skSeed, adrs, sk, 0);
#endif

                adrs.SetAdrsType(Adrs.WOTS_HASH);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress(i);
                adrs.SetHashAddress(0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Chain(0, w - 1, pkSeed, adrs, tmpConcat.AsSpan(engine.N * (int)i, engine.N));
#else
                tmp[i] = Chain(sk, 0, w - 1, pkSeed, adrs);
#endif
            }

            wotspkAdrs.SetAdrsType(Adrs.WOTS_PK);
            wotspkAdrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            engine.T_l(pkSeed, wotspkAdrs, tmpConcat, output);
#else
            engine.T_l(pkSeed, wotspkAdrs, Arrays.ConcatenateAll(tmp), output);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // #Input: Input string X, start index i, number of steps s, public seed PK.seed, address Adrs
        // #Output: value of F iterated s times on X
        private bool Chain(uint i, uint s, byte[] pkSeed, Adrs adrs, Span<byte> X)
        {
            if (s == 0)
                return true;

            // TODO Check this since the highest we use is i + s - 1
            if ((i + s) > (this.w - 1))
                return false;

            for (uint j = 0; j < s; ++j)
            {
                adrs.SetHashAddress(i + j);
                engine.F(pkSeed, adrs, X);
            }

            return true;
        }
#else
        // #Input: Input string X, start index i, number of steps s, public seed PK.seed, address Adrs
        // #Output: value of F iterated s times on X
        private byte[] Chain(byte[] X, uint i, uint s, byte[] pkSeed, Adrs adrs)
        {
            if (s == 0)
                return Arrays.Clone(X);

            // TODO Check this since the highest we use is i + s - 1
            if ((i + s) > (this.w - 1))
                return null;

            byte[] result = X;
            for (uint j = 0; j < s; ++j)
            {
                adrs.SetHashAddress(i + j);
                result = engine.F(pkSeed, adrs, result);
            }
            return result;
        }
#endif

        // #Input: Message M, secret seed SK.seed, public seed PK.seed, address Adrs
        // #Output: WOTS+ signature sig
        internal byte[] Sign(byte[] M, byte[] skSeed, byte[] pkSeed, Adrs paramAdrs)
        {
            Adrs adrs = new Adrs(paramAdrs);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<uint> msg = stackalloc uint[engine.WOTS_LEN];

            // convert message to base w
            BaseW(M, w, msg[..engine.WOTS_LEN1]);
#else
            uint[] msg = new uint[engine.WOTS_LEN];

            // convert message to base w
            BaseW(M, 0, w, msg, 0, engine.WOTS_LEN1);
#endif

            // compute checksum
            uint csum = 0;
            for (int i = 0; i < engine.WOTS_LEN1; i++)
            {
                csum += w - 1 - msg[i];
            }

            // convert csum to base w
            if ((engine.WOTS_LOGW % 8) != 0)
            {
                csum <<= 8 - (engine.WOTS_LEN2 * engine.WOTS_LOGW % 8);
            }
            int len_2_bytes = (engine.WOTS_LEN2 * engine.WOTS_LOGW + 7) / 8;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> csum_bytes = stackalloc byte[4];
            Pack.UInt32_To_BE(csum, csum_bytes);
            BaseW(csum_bytes[^len_2_bytes..], w, msg[engine.WOTS_LEN1..]);

            byte[] sigConcat = new byte[engine.WOTS_LEN * engine.N];
#else
            byte[] csum_bytes = Pack.UInt32_To_BE(csum);
            BaseW(csum_bytes, 4 - len_2_bytes, w, msg, engine.WOTS_LEN1, engine.WOTS_LEN2);

            byte[][] sig = new byte[engine.WOTS_LEN][];
            byte[] sk = new byte[engine.N];
#endif
            for (int i = 0; i < engine.WOTS_LEN; i++)
            {
                adrs.SetAdrsType(Adrs.WOTS_PRF);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress((uint)i);
                adrs.SetHashAddress(0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                engine.PRF(pkSeed, skSeed, adrs, sigConcat, engine.N * i);
#else
                engine.PRF(pkSeed, skSeed, adrs, sk, 0);
#endif

                adrs.SetAdrsType(Adrs.WOTS_HASH);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress((uint)i);
                adrs.SetHashAddress(0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Chain(0, msg[i], pkSeed, adrs, sigConcat.AsSpan(engine.N * i, engine.N));
#else
                sig[i] = Chain(sk, 0, msg[i], pkSeed, adrs);
#endif
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return sigConcat;
#else
            return Arrays.ConcatenateAll(sig);
#endif
        }

        //
        // Input: len_X-byte string X, int w, output length out_len
        // Output: outLen int array basew
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void BaseW(ReadOnlySpan<byte> X, uint w, Span<uint> output)
        {
            int total = 0;
            int bits = 0;
            int XOff = 0;
            int outOff = 0;

            for (int consumed = 0; consumed < output.Length; consumed++)
            {
                if (bits == 0)
                {
                    total = X[XOff++];
                    bits += 8;
                }

                bits -= engine.WOTS_LOGW;
                output[outOff++] = (uint)((total >> bits) & (w - 1));
            }
        }
#else
        internal void BaseW(byte[] X, int XOff, uint w, uint[] output, int outOff, int outLen)
        {
            int total = 0;
            int bits = 0;

            for (int consumed = 0; consumed < outLen; consumed++)
            {
                if (bits == 0)
                {
                    total = X[XOff++];
                    bits += 8;
                }

                bits -= engine.WOTS_LOGW;
                output[outOff++] = (uint)((total >> bits) & (w - 1));
            }
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void PKFromSig(byte[] sig, byte[] M, byte[] pkSeed, Adrs adrs, Span<byte> output)
#else
        internal void PKFromSig(byte[] sig, byte[] M, byte[] pkSeed, Adrs adrs, byte[] output)
#endif
        {
            Adrs wotspkAdrs = new Adrs(adrs);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<uint> msg = stackalloc uint[engine.WOTS_LEN];

            // convert message to base w
            BaseW(M, w, msg[..engine.WOTS_LEN1]);
#else
            uint[] msg = new uint[engine.WOTS_LEN];

            // convert message to base w
            BaseW(M, 0, w, msg, 0, engine.WOTS_LEN1);
#endif

            // compute checksum
            uint csum = 0;
            for (int i = 0; i < engine.WOTS_LEN1; i++)
            {
                csum += w - 1 - msg[i];
            }

            // convert csum to base w
            csum <<= 8 - (engine.WOTS_LEN2 * engine.WOTS_LOGW % 8);
            int len_2_bytes = (engine.WOTS_LEN2 * engine.WOTS_LOGW + 7) / 8;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> csum_bytes = stackalloc byte[4];
            Pack.UInt32_To_BE(csum, csum_bytes);
            BaseW(csum_bytes[^len_2_bytes..], w, msg[engine.WOTS_LEN1..]);

            byte[] tmpConcat = new byte[engine.WOTS_LEN * engine.N];
#else
            byte[] csum_bytes = Pack.UInt32_To_BE(csum);
            BaseW(csum_bytes, 4 - len_2_bytes, w, msg, engine.WOTS_LEN1, engine.WOTS_LEN2);

            byte[] sigI = new byte[engine.N];
            byte[][] tmp = new byte[engine.WOTS_LEN][];
#endif
            for (int i = 0; i < engine.WOTS_LEN; i++)
            {
                adrs.SetChainAddress((uint)i);

                int sigPos = engine.N * i;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Array.Copy(sig, sigPos, tmpConcat, sigPos, engine.N);
                Chain(msg[i], w - 1 - msg[i], pkSeed, adrs, tmpConcat.AsSpan(sigPos, engine.N));
#else
                Array.Copy(sig, sigPos, sigI, 0, engine.N);
                tmp[i] = Chain(sigI, msg[i], w - 1 - msg[i], pkSeed, adrs);
#endif
            }

            wotspkAdrs.SetAdrsType(Adrs.WOTS_PK);
            wotspkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress());

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            engine.T_l(pkSeed, wotspkAdrs, tmpConcat, output);
#else
            engine.T_l(pkSeed, wotspkAdrs, Arrays.ConcatenateAll(tmp), output);
#endif
        }
    }
}
