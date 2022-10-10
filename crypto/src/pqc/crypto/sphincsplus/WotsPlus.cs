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

        internal byte[] PKGen(byte[] skSeed, byte[] pkSeed, Adrs paramAdrs)
        {
            Adrs wotspkAdrs = new Adrs(paramAdrs); // copy address to create OTS public key address

            byte[][] tmp = new byte[engine.WOTS_LEN][];
            byte[] sk = new byte[engine.N];
            for (uint i = 0; i < engine.WOTS_LEN; i++)
            {
                Adrs adrs = new Adrs(paramAdrs);
                adrs.SetAdrsType(Adrs.WOTS_PRF);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress(i);
                adrs.SetHashAddress(0);

                engine.PRF(pkSeed, skSeed, adrs, sk, 0);

                adrs.SetAdrsType(Adrs.WOTS_HASH);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress(i);
                adrs.SetHashAddress(0);

                tmp[i] = Chain(sk, 0, w - 1, pkSeed, adrs);
            }

            wotspkAdrs.SetAdrsType(Adrs.WOTS_PK);
            wotspkAdrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());

            return engine.T_l(pkSeed, wotspkAdrs, Arrays.ConcatenateAll(tmp));
        }

        // #Input: Input string X, start index i, number of steps s, public seed PK.seed, address Adrs
        // #Output: value of F iterated s times on X
        internal byte[] Chain(byte[] X, uint i, uint s, byte[] pkSeed, Adrs adrs)
        {
            if (s == 0)
                return Arrays.Clone(X);

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

        // #Input: Message M, secret seed SK.seed, public seed PK.seed, address Adrs
        // #Output: WOTS+ signature sig
        internal byte[] Sign(byte[] M, byte[] skSeed, byte[] pkSeed, Adrs paramAdrs)
        {
            Adrs adrs = new Adrs(paramAdrs);

            uint[] msg = new uint[engine.WOTS_LEN];

            // convert message to base w
            BaseW(M, 0, w, msg, 0, engine.WOTS_LEN1);

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
            byte[] csum_bytes = Pack.UInt32_To_BE(csum);
            BaseW(csum_bytes, 4 - len_2_bytes, w, msg, engine.WOTS_LEN1, engine.WOTS_LEN2);

            byte[][] sig = new byte[engine.WOTS_LEN][];
            byte[] sk = new byte[engine.N];
            for (uint i = 0; i < engine.WOTS_LEN; i++)
            {
                adrs.SetAdrsType(Adrs.WOTS_PRF);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress(i);
                adrs.SetHashAddress(0);

                engine.PRF(pkSeed, skSeed, adrs, sk, 0);

                adrs.SetAdrsType(Adrs.WOTS_HASH);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress(i);
                adrs.SetHashAddress(0);

                sig[i] = Chain(sk, 0, msg[i], pkSeed, adrs);
            }

            return Arrays.ConcatenateAll(sig);
        }

        //
        // Input: len_X-byte string X, int w, output length out_len
        // Output: outLen int array basew
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

        internal byte[] PKFromSig(byte[] sig, byte[] M, byte[] pkSeed, Adrs adrs)
        {
            Adrs wotspkAdrs = new Adrs(adrs);

            uint[] msg = new uint[engine.WOTS_LEN];

            // convert message to base w
            BaseW(M, 0, w, msg, 0, engine.WOTS_LEN1);

            // compute checksum
            uint csum = 0;
            for (int i = 0; i < engine.WOTS_LEN1; i++)
            {
                csum += w - 1 - msg[i];
            }

            // convert csum to base w
            csum <<= 8 - (engine.WOTS_LEN2 * engine.WOTS_LOGW % 8);
            int len_2_bytes = (engine.WOTS_LEN2 * engine.WOTS_LOGW + 7) / 8;
            byte[] csum_bytes = Pack.UInt32_To_BE(csum);
            BaseW(csum_bytes, 4 - len_2_bytes, w, msg, engine.WOTS_LEN1, engine.WOTS_LEN2);

            byte[] sigI = new byte[engine.N];
            byte[][] tmp = new byte[engine.WOTS_LEN][];
            for (uint i = 0; i < engine.WOTS_LEN; i++)
            {
                adrs.SetChainAddress(i);
                Array.Copy(sig, i * engine.N, sigI, 0, engine.N);
                tmp[i] = Chain(sigI, msg[i], w - 1 - msg[i], pkSeed, adrs);
            }

            wotspkAdrs.SetAdrsType(Adrs.WOTS_PK);
            wotspkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress());

            return engine.T_l(pkSeed, wotspkAdrs, Arrays.ConcatenateAll(tmp));
        }
    }
}
