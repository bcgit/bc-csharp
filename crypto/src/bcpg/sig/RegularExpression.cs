using System;
using System.Text.RegularExpressions;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
     * Regexp Packet - RFC 4880 5.2.3.14. Note: the RFC says the byte encoding is to be null terminated.
     */
    public class RegularExpression
        : SignatureSubpacket
    {
        public RegularExpression(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.RegExp, critical, isLongLength, data)
        {
            if (data[data.Length - 1] != 0)
                throw new ArgumentException("data in regex missing null termination");
        }

        public RegularExpression(bool critical, string regex)
            : base(SignatureSubpacketTag.RegExp, critical, false, ToNullTerminatedUtf8ByteArray(regex))
        {
        }

        // last byte is null terminator
        public string Regex => Strings.FromUtf8ByteArray(data, 0, data.Length - 1);

        public byte[] GetRawRegex() => Arrays.Clone(data);

        private static byte[] ToNullTerminatedUtf8ByteArray(string str)
        {
            byte[] utf8 = Strings.ToUtf8ByteArray(str, preAlloc: 0, postAlloc: 1);
            utf8[utf8.Length - 1] = 0x00;
            return utf8;
        }
    }
}
