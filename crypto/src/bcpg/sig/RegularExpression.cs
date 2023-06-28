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

        public string Regex
        {
            // last byte is null terminator
            get { return Strings.FromUtf8ByteArray(data, 0, data.Length - 1); }
        }

        public byte[] GetRawRegex() => Arrays.Clone(data);

        private static byte[] ToNullTerminatedUtf8ByteArray(string str)
        {
            byte[] utf8 = Strings.ToUtf8ByteArray(str);
            return Arrays.Append(utf8, 0x00);
        }
    }
}
