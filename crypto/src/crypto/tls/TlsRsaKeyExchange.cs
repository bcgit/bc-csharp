using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Tls
{
    public static class TlsRsaKeyExchange
    {
        public const int PreMasterSecretLength = 48;

        public static byte[] DecryptPreMasterSecret(byte[] buf, int off, int len, RsaKeyParameters privateKey,
            int protocolVersion, SecureRandom secureRandom)
        {
            if ((protocolVersion & 0xFFFF) != protocolVersion)
                throw new ArgumentException("must be a 16 bit value", nameof(protocolVersion));

            RsaPkcs1Utilities.ValidityCheck protocolVersionCheck = (_buf, _off, _len) =>
                Pack.BE_To_UInt16(_buf, _off) ^ protocolVersion;

            return RsaPkcs1Utilities.DecryptToFixedLength(PreMasterSecretLength, buf, off, len, privateKey,
                secureRandom, protocolVersionCheck);
        }
 
        public static int GetInputLimit(RsaKeyParameters privateKey) => RsaPkcs1Utilities.GetInputLimit(privateKey);
    }
}
