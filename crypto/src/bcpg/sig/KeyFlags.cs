using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * Packet holding the key flag values.
    */
    public class KeyFlags
        : SignatureSubpacket
    {
        public const int CertifyOther = 0x01;
        public const int SignData = 0x02;
        public const int EncryptComms = 0x04;
        public const int EncryptStorage = 0x08;
        public const int Split = 0x10;
        public const int Authentication = 0x20;
        public const int Shared = 0x80;

        private static int DataToFlags(byte[] data)
        {
            int flags = 0, bytes = System.Math.Min(4, data.Length);
            for (int i = 0; i < bytes; ++i)
            {
                flags |= data[i] << (i * 8);
            }
            return flags;
        }

        private static byte[] FlagsToData(int flags)
        {
            int bits = 32 - Integers.NumberOfLeadingZeros(flags);
            int bytes = (bits + 7) / 8;

            byte[] data = new byte[bytes];
            for (int i = 0; i < bytes; ++i)
            {
                data[i] = (byte)(flags >> (i * 8));
            }
            return data;
        }

        public KeyFlags(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.KeyFlags, critical, isLongLength, data)
        {
        }

        public KeyFlags(bool critical, int flags)
            : base(SignatureSubpacketTag.KeyFlags, critical, isLongLength: false, FlagsToData(flags))
        {
        }

        /// <summary>
        /// Return the flag values contained in the first 4 octets (note: at the moment
        /// the standard only uses the first one).
        /// </summary>
        public int Flags => DataToFlags(Data);
    }
}
