using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket encoding custom notations. Notations are key-value pairs.</summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.16">RFC4880 - Notation Data</see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data">RFC9580 - Notation Data</see>
    /// </remarks>
    public class NotationData
        : SignatureSubpacket
    {
        public const int HeaderFlagLength = 4;
        public const int HeaderNameLength = 2;
        public const int HeaderValueLength = 2;

        public NotationData(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.NotationData, critical, isLongLength, VerifyData(data))
        {
        }

        public NotationData(bool critical, bool humanReadable, string notationName, string notationValue)
            : base(SignatureSubpacketTag.NotationData, critical, isLongLength: false,
                CreateData(humanReadable, notationName, notationValue))
        {
        }

        private static byte[] CreateData(bool humanReadable, string notationName, string notationValue)
        {
            MemoryStream os = new MemoryStream();

            // (4 octets of flags, 2 octets of name length (M),
            // 2 octets of value length (N),
            // M octets of name data,
            // N octets of value data)

            // flags
            os.WriteByte(humanReadable ? (byte)0x80 : (byte)0x00);
            os.WriteByte(0x0);
            os.WriteByte(0x0);
            os.WriteByte(0x0);

            byte[] nameData, valueData = null;
            int nameLength, valueLength;

            nameData = Strings.ToUtf8ByteArray(notationName);
            nameLength = System.Math.Min(nameData.Length, 0xFF);

            valueData = Strings.ToUtf8ByteArray(notationValue);
            valueLength = System.Math.Min(valueData.Length, 0xFF);

            // name length
            os.WriteByte((byte)(nameLength >> 8));
            os.WriteByte((byte)(nameLength >> 0));

            // value length
            os.WriteByte((byte)(valueLength >> 8));
            os.WriteByte((byte)(valueLength >> 0));

            // name
            os.Write(nameData, 0, nameLength);

            // value
            os.Write(valueData, 0, valueLength);

            return os.ToArray();
        }

        private static byte[] VerifyData(byte[] data)
        {
            int headerLength = HeaderFlagLength + HeaderNameLength + HeaderValueLength;
            if (data.Length < headerLength)
                throw new ArgumentException($"Malformed notation data encoding (too short): {data.Length}",
                    nameof(data));

            int nameOffset = HeaderFlagLength;
            int nameLength = (int)Pack.BE_To_UInt16(data, nameOffset);

            int valueOffset = nameOffset + HeaderNameLength;
            int valueLength = (int)Pack.BE_To_UInt16(data, valueOffset);

            int claimedLength = headerLength + nameLength + valueLength;
            if (claimedLength > data.Length)
                throw new ArgumentException("Malformed notation data encoding.", nameof(data));

            return data;
        }

        public bool IsHumanReadable => (Data[0] & 0x80) != 0;

        public string GetNotationName()
        {
            var data = Data;
            int nameLength = ((data[HeaderFlagLength] << 8) + (data[HeaderFlagLength + 1] << 0));
            int namePos = HeaderFlagLength + HeaderNameLength + HeaderValueLength;

            return Strings.FromByteArray(data, namePos, nameLength);
        }

        public string GetNotationValue()
        {
            var data = Data;
            int nameLength = ((data[HeaderFlagLength] << 8) + (data[HeaderFlagLength + 1] << 0));
            int valueLength = ((data[HeaderFlagLength + HeaderNameLength] << 8) + (data[HeaderFlagLength + HeaderNameLength + 1] << 0));
            int valuePos = HeaderFlagLength + HeaderNameLength + HeaderValueLength + nameLength;

            return Strings.FromByteArray(data, valuePos, valueLength);
        }

        public byte[] GetNotationValueBytes()
        {
            var data = Data;
            int nameLength = ((data[HeaderFlagLength] << 8) + (data[HeaderFlagLength + 1] << 0));
            int valueLength = ((data[HeaderFlagLength + HeaderNameLength] << 8) + (data[HeaderFlagLength + HeaderNameLength + 1] << 0));
            int valuePos = HeaderFlagLength + HeaderNameLength + HeaderValueLength + nameLength;

            byte[] bytes = new byte[valueLength];
            Array.Copy(data, valuePos, bytes, 0, valueLength);
            return bytes;
        }
    }
}
