using System;

namespace Org.BouncyCastle.Bcpg
{
    public sealed class Crc24
    {
        private const int Crc24Init = 0x0b704ce;
        private const int Crc24Poly = 0x1864cfb;

        private int m_crc = Crc24Init;

        public Crc24()
        {
        }

        public void Update(byte b)
        {
            m_crc ^= (int)b << 16;
            for (int i = 0; i < 8; i++)
            {
                int carry = -((m_crc >> 23) & 1) & Crc24Poly;

                m_crc <<= 1;
                m_crc ^= carry;
            }
        }

        public int Value => m_crc;

		public void Reset()
        {
            m_crc = Crc24Init;
        }
    }
}
