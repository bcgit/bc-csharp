using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    internal static class Cbd
    {
        internal static void Eta(Poly r, byte[] bytes, int eta)
        {
            switch (eta)
            {
            case 2:
            {
                for (int i = 0; i < KyberEngine.N / 8; i++)
                {
                    uint t = Pack.LE_To_UInt32(bytes, 4 * i);
                    uint d = t & 0x55555555;
                    d += (t >> 1) & 0x55555555;
                    for (int j = 0; j < 8; j++)
                    {
                        short a = (short)((d >> (4 * j + 0)) & 0x3);
                        short b = (short)((d >> (4 * j + eta)) & 0x3);
                        r.m_coeffs[8 * i + j] = (short) (a - b);
                    }
                }
                break;
            }
            case 3:
            {
                for (int i = 0; i < KyberEngine.N / 4; i++)
                {
                    uint t = Pack.LE_To_UInt24(bytes, 3 * i);
                    uint d = t & 0x00249249;
                    d += (t >> 1) & 0x00249249;
                    d += (t >> 2) & 0x00249249;

                    for (int j = 0; j < 4; j++)
                    {
                        short a = (short)((d >> (6 * j + 0)) & 0x7);
                        short b = (short)((d >> (6 * j + 3)) & 0x7);
                        r.m_coeffs[4 * i + j] = (short)(a - b);
                    }
                }
                break;
            }
            default:
                throw new ArgumentException("Wrong Eta");
            }
        }
    }
}
