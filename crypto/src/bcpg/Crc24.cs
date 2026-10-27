namespace Org.BouncyCastle.Bcpg
{
    /// <summary>The CRC-24 checksum used by ASCII armor.</summary>
    public sealed class Crc24
    {
        private const int Crc24Init = 0x0b704ce;
        private const int Crc24Poly = 0x1864cfb;

        private static readonly int[] Table0, Table8, Table16;

        static Crc24()
        {
            int[] table0 = new int[256];
            int[] table8 = new int[256];
            int[] table16 = new int[256];

            int crc = 0x800000;
            for (int i = 1; i < 256; i <<= 1)
            {
                int carry = ((crc << 8) >> 31) & Crc24Poly;
                crc = (crc << 1) ^ carry;

                for (int j = 0; j < i; ++j)
                {
                    table0[i + j] = crc ^ table0[j];
                }
            }

            for (int i = 1; i < 256; ++i)
            {
                int crc0 = table0[i];
                int crc8 = ((crc0 & 0xFFFF) << 8) ^ table0[(crc0 >> 16) & 255];
                int crc16 = ((crc8 & 0xFFFF) << 8) ^ table0[(crc8 >> 16) & 255];

                table8[i] = crc8;
                table16[i] = crc16;
            }

            Table0 = table0;
            Table8 = table8;
            Table16 = table16;
        }

        private int m_crc = Crc24Init;

        /// <summary>Create a new <see cref="Crc24"/>.</summary>
        public Crc24()
        {
        }

        /// <summary>Add a byte to the checksum.</summary>
        /// <param name="b">The byte.</param>
        public void Update(byte b)
        {
            int index = (b ^ (m_crc >> 16)) & 255;
            m_crc = (m_crc << 8) ^ Table0[index];
        }

        /// <summary>Add three bytes to the checksum.</summary>
        /// <param name="buf">The buffer holding the bytes.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which the three bytes start.</param>
        public void Update3(byte[] buf, int off)
        {
            m_crc = Table16[(buf[off + 0] ^ (m_crc >> 16)) & 255]
                  ^ Table8[(buf[off + 1] ^ (m_crc >> 8)) & 255]
                  ^ Table0[(buf[off + 2] ^ m_crc) & 255];
        }

        /// <summary>Gets the value.</summary>
        public int Value => m_crc & 0xFFFFFF;

        /// <summary>Reset the checksum to its initial value.</summary>
        public void Reset()
        {
            m_crc = Crc24Init;
        }
    }
}
