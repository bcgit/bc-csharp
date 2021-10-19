using System;

namespace Org.BouncyCastle.Bcpg
{
    public class UnsupportedPacketVersionException
        : Exception
    {
        public UnsupportedPacketVersionException(string msg)
            : base(msg)
        {
        }
    }
}
