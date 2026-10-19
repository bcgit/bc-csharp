using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Attr
{
    /// <remarks>Basic type for a image attribute packet.</remarks>
    public class ImageAttrib
        : UserAttributeSubpacket
    {
        /// <summary>The image formats of an image attribute.</summary>
        public enum Format : byte
        {
            Jpeg = 1
        }

        private readonly int m_hdrLength;
        private readonly int m_version;
        private readonly int m_encoding;
        private readonly byte[] m_imageData;

        /// <summary>Create a new <see cref="ImageAttrib"/>.</summary>
        /// <param name="data">The data.</param>
        public ImageAttrib(byte[] data)
            : this(forceLongLength: false, data)
        {
        }

        /// <summary>Create a new <see cref="ImageAttrib"/>.</summary>
        /// <param name="forceLongLength">true if force long length, false otherwise.</param>
        /// <param name="data">The data.</param>
        public ImageAttrib(bool forceLongLength, byte[] data)
            : base(UserAttributeSubpacketTag.ImageAttribute, forceLongLength, data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data.Length < 4)
                throw new ArgumentException("Image header truncated", nameof(data));

            // NB: due to a historical accident, encoded as a little-endian number.
            m_hdrLength = Pack.LE_To_UInt16(data, 0);
            m_version = data[2];
            m_encoding = data[3];

            // TODO Check header length is appropriate for version?

            if (data.Length < m_hdrLength)
                throw new ArgumentException($"Data length {data.Length} less than declared header length {m_hdrLength}");

            m_imageData = Arrays.CopyOfRange(data, m_hdrLength, data.Length);
        }

        /// <summary>Create a new <see cref="ImageAttrib"/>.</summary>
        /// <param name="imageType">The image type.</param>
        /// <param name="imageData">The image data.</param>
        public ImageAttrib(Format imageType, byte[] imageData)
            : this(ToByteArray(imageType, imageData))
        {
        }

        private static byte[] ToByteArray(Format imageType, byte[] imageData)
        {
            int hdrLength = 16;
            byte[] data = new byte[hdrLength + imageData.Length];
            Pack.UInt16_To_LE((ushort)hdrLength, data, 0);
            data[2] = 0x01;
            data[3] = (byte)imageType;
            //Arrays.Fill<byte>(data, 4, 16, 0x00); // 12 reserved octets, all of which MUST be set to 0
            imageData.CopyTo(data, hdrLength);
            return data;
        }

        /// <summary>Gets the version.</summary>
        public virtual int Version => m_version;

        /// <summary>Gets the encoding.</summary>
        public virtual int Encoding => m_encoding;

        /// <summary>Return the image data.</summary>
        public virtual byte[] GetImageData() => m_imageData;
    }
}
