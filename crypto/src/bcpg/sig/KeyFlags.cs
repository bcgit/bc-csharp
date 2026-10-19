using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket encoding the capabilities / intended uses of a key.</summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.21">RFC4880 - Key Flags</see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-key-flags">RFC9580 - Key Flags</see>
    /// </remarks>
    public class KeyFlags
        : SignatureSubpacket
    {
        /// <summary>The <c>CertifyOther</c> constant, with the value <c>0x01</c>.</summary>
        public const int CertifyOther = 0x01;
        /// <summary>The <c>SignData</c> constant, with the value <c>0x02</c>.</summary>
        public const int SignData = 0x02;
        /// <summary>The <c>EncryptComms</c> constant, with the value <c>0x04</c>.</summary>
        public const int EncryptComms = 0x04;
        /// <summary>The <c>EncryptStorage</c> constant, with the value <c>0x08</c>.</summary>
        public const int EncryptStorage = 0x08;
        /// <summary>The <c>Split</c> constant, with the value <c>0x10</c>.</summary>
        public const int Split = 0x10;
        /// <summary>The <c>Authentication</c> constant, with the value <c>0x20</c>.</summary>
        public const int Authentication = 0x20;
        /// <summary>The <c>Shared</c> constant, with the value <c>0x80</c>.</summary>
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
            int bits = Integers.BitLength(flags);
            int bytes = (bits + 7) / 8;

            byte[] data = new byte[bytes];
            for (int i = 0; i < bytes; ++i)
            {
                data[i] = (byte)(flags >> (i * 8));
            }
            return data;
        }

        /// <summary>Create a new <see cref="KeyFlags"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if is long length, false otherwise.</param>
        /// <param name="data">The data.</param>
        public KeyFlags(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.KeyFlags, critical, isLongLength, data)
        {
        }

        /// <summary>Create a new <see cref="KeyFlags"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="flags">The flags.</param>
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
