using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving whether or not is revocable.
    */
    public class Revocable
        : SignatureSubpacket
    {
        private static byte[] BooleanToByteArray(bool value)
        {
            return new byte[1]{ Convert.ToByte(value) };
        }

        public Revocable(
            bool    critical,
            bool    isLongLength,
            byte[]  data)
            : base(SignatureSubpacketTag.Revocable, critical, isLongLength, data)
        {
        }

        public Revocable(
            bool    critical,
            bool    isRevocable)
            : base(SignatureSubpacketTag.Revocable, critical, false, BooleanToByteArray(isRevocable))
        {
        }

        public bool IsRevocable()
        {
            return data[0] != 0;
        }
    }
}
