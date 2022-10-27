using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving signature creation time.
    */
    public class Exportable
        : SignatureSubpacket
    {
        private static byte[] BooleanToByteArray(bool val)
        {
            return new byte[1]{ Convert.ToByte(val) };
        }

        public Exportable(
            bool    critical,
            bool    isLongLength,
            byte[]  data)
            : base(SignatureSubpacketTag.Exportable, critical, isLongLength, data)
        {
        }

        public Exportable(
            bool    critical,
            bool    isExportable)
            : base(SignatureSubpacketTag.Exportable, critical, false, BooleanToByteArray(isExportable))
        {
        }

        public bool IsExportable()
        {
            return data[0] != 0;
        }
    }
}
