using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal sealed class WotsPlus
    {
        private readonly SlhDsaEngine m_engine;

        internal WotsPlus(SlhDsaEngine engine)
        {
            m_engine = engine;
        }

        internal void PKGen(byte[] skSeed, byte[] pkSeed, Adrs paramAdrs, byte[] output, int outputOff)
        {
            int n = m_engine.N;
            int wotsLen = m_engine.WotsLen;
            uint w = (uint)m_engine.WotsW;

            Adrs wotspkAdrs = new Adrs(paramAdrs); // copy address to create OTS public key address

            byte[] tmpConcat = new byte[wotsLen * n];

            for (int i = 0; i < wotsLen; i++)
            {
                Adrs adrs = new Adrs(paramAdrs);
                adrs.SetTypeAndClear(Adrs.WotsPrf);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress((uint)i);
                adrs.SetHashAddress(0U);

                m_engine.Prf(adrs, skSeed, tmpConcat, n * i);

                adrs.SetTypeAndClear(Adrs.WotsHash);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress((uint)i);
                adrs.SetHashAddress(0U);

                Chain(0U, w - 1U, pkSeed, adrs, tmpConcat, n * i);
            }

            wotspkAdrs.SetTypeAndClear(Adrs.WotsPK);
            wotspkAdrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());

            m_engine.T_l(wotspkAdrs, tmpConcat, output, outputOff);
        }

        private void Chain(uint i, uint s, byte[] pkSeed, Adrs adrs, byte[] X, int XOff)
        {
            // TODO Check this since the highest we use is i + s - 1
            if ((i + s) > (m_engine.WotsW - 1))
                throw new InvalidOperationException();

            for (uint j = 0; j < s; ++j)
            {
                adrs.SetHashAddress(i + j);
                m_engine.F(adrs, X, XOff);
            }
        }

        internal void Sign(byte[] M, byte[] skSeed, byte[] pkSeed, Adrs paramAdrs, byte[] output, int outputOff)
        {
            int n = m_engine.N;
            int wotsLen = m_engine.WotsLen;
            int wotsLen1 = m_engine.WotsLen1;
            int wotsLen2 = m_engine.WotsLen2;
            int wotsLogW = m_engine.WotsLogW;
            uint w = (uint)m_engine.WotsW;

            Adrs adrs = new Adrs(paramAdrs);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<uint> msg = stackalloc uint[wotsLen];

            // convert message to base w
            BaseW(M, w, msg[..wotsLen1]);
#else
            uint[] msg = new uint[wotsLen];

            // convert message to base w
            BaseW(M, 0, w, msg, 0, wotsLen1);
#endif

            // compute checksum
            uint csum = 0;
            for (int i = 0; i < wotsLen1; i++)
            {
                csum += w - 1 - msg[i];
            }

            // convert csum to base w
            if ((wotsLogW % 8) != 0)
            {
                csum <<= 8 - (wotsLen2 * wotsLogW % 8);
            }
            int len_2_bytes = (wotsLen2 * wotsLogW + 7) / 8;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> csum_bytes = stackalloc byte[4];
            Pack.UInt32_To_BE(csum, csum_bytes);
            BaseW(csum_bytes[^len_2_bytes..], w, msg[wotsLen1..]);
#else
            byte[] csum_bytes = Pack.UInt32_To_BE(csum);
            BaseW(csum_bytes, 4 - len_2_bytes, w, msg, wotsLen1, wotsLen2);
#endif

            for (int i = 0; i < wotsLen; i++)
            {
                adrs.SetTypeAndClear(Adrs.WotsPrf);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress((uint)i);
                adrs.SetHashAddress(0);

                m_engine.Prf(adrs, skSeed, output, outputOff + n * i);

                adrs.SetTypeAndClear(Adrs.WotsHash);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetChainAddress((uint)i);
                adrs.SetHashAddress(0);

                Chain(0U, msg[i], pkSeed, adrs, output, outputOff + n * i);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void BaseW(ReadOnlySpan<byte> X, uint w, Span<uint> output)
        {
            int wotsLogW = m_engine.WotsLogW;

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

                bits -= wotsLogW;
                output[outOff++] = (uint)((total >> bits) & (w - 1));
            }
        }
#else
        internal void BaseW(byte[] X, int XOff, uint w, uint[] output, int outOff, int outLen)
        {
            int wotsLogW = m_engine.WotsLogW;

            int total = 0;
            int bits = 0;

            for (int consumed = 0; consumed < outLen; consumed++)
            {
                if (bits == 0)
                {
                    total = X[XOff++];
                    bits += 8;
                }

                bits -= wotsLogW;
                output[outOff++] = (uint)((total >> bits) & (w - 1));
            }
        }
#endif

        internal void PKFromSig(byte[] sig, int sigOff, byte[] M, byte[] pkSeed, Adrs adrs, byte[] output, int outputOff)
        {
            int n = m_engine.N;
            int wotsLen = m_engine.WotsLen;
            int wotsLen1 = m_engine.WotsLen1;
            int wotsLen2 = m_engine.WotsLen2;
            int wotsLogW = m_engine.WotsLogW;
            uint w = (uint)m_engine.WotsW;

            Adrs wotspkAdrs = new Adrs(adrs);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<uint> msg = stackalloc uint[wotsLen];

            // convert message to base w
            BaseW(M, w, msg[..wotsLen1]);
#else
            uint[] msg = new uint[wotsLen];

            // convert message to base w
            BaseW(M, 0, w, msg, 0, wotsLen1);
#endif

            // compute checksum
            uint csum = 0;
            for (int i = 0; i < wotsLen1; i++)
            {
                csum += w - 1 - msg[i];
            }

            // convert csum to base w
            csum <<= 8 - (wotsLen2 * wotsLogW % 8);
            int len_2_bytes = (wotsLen2 * wotsLogW + 7) / 8;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> csum_bytes = stackalloc byte[4];
            Pack.UInt32_To_BE(csum, csum_bytes);
            BaseW(csum_bytes[^len_2_bytes..], w, msg[wotsLen1..]);
#else
            byte[] csum_bytes = Pack.UInt32_To_BE(csum);
            BaseW(csum_bytes, 4 - len_2_bytes, w, msg, wotsLen1, wotsLen2);
#endif

            byte[] tmpConcat = new byte[wotsLen * n];

            for (int i = 0; i < wotsLen; i++)
            {
                adrs.SetChainAddress((uint)i);

                int sigPos = n * i;
                Array.Copy(sig, sigOff + sigPos, tmpConcat, sigPos, n);
                Chain(msg[i], w - 1U - msg[i], pkSeed, adrs, tmpConcat, sigPos);
            }

            wotspkAdrs.SetTypeAndClear(Adrs.WotsPK);
            wotspkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress());

            m_engine.T_l(wotspkAdrs, tmpConcat, output, outputOff);
        }
    }
}
