using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>
    /// Signature Subpacket containing a regular expression limiting the scope of the signature.
    /// </summary>
    /// <remarks>
    /// Note: the RFC says the byte encoding is to be null terminated.
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.14">
    /// RFC4880 - Regular Expression
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-regular-expression">
    /// RFC9580 - Regular Expression
    /// </see>
    /// </para>
    /// </remarks>
    public class RegularExpression
        : SignatureSubpacket
    {
        public RegularExpression(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.RegExp, critical, isLongLength, data)
        {
            if (data.Length < 1 || data[data.Length - 1] != 0)
                throw new ArgumentException("data in regex missing null termination");
        }

        public RegularExpression(bool critical, string regex)
            : base(SignatureSubpacketTag.RegExp, critical, isLongLength: false, ToNullTerminatedUtf8ByteArray(regex))
        {
        }

        [Obsolete("Use 'GetRegex()' instead")]
        public string Regex => Strings.FromUtf8ByteArray(Data, 0, Data.Length - 1);

        public byte[] GetRawRegex() => GetData();

        // last byte is null terminator
        public string GetRegex() => Strings.FromUtf8ByteArray(Data, 0, Data.Length - 1);

        private static byte[] ToNullTerminatedUtf8ByteArray(string str)
        {
            byte[] utf8 = Strings.ToUtf8ByteArray(str, preAlloc: 0, postAlloc: 1);
            utf8[utf8.Length - 1] = 0x00;
            return utf8;
        }
    }
}
