using System;
using System.Collections.Generic;

using Org.BouncyCastle.Bcpg.Attr;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>A generator for user attribute subpacket vectors.</summary>
    public class PgpUserAttributeSubpacketVectorGenerator
    {
        private readonly List<UserAttributeSubpacket> list = new List<UserAttributeSubpacket>();

        /// <summary>Set an image attribute.</summary>
        /// <param name="imageType">The image format.</param>
        /// <param name="imageData">The image data.</param>
        public virtual void SetImageAttribute(ImageAttrib.Format imageType, byte[] imageData)
        {
            if (imageData == null)
                throw new ArgumentException("attempt to set null image", "imageData");

            list.Add(new ImageAttrib(imageType, imageData));
        }

        /// <summary>Generate the vector of subpackets.</summary>
        /// <returns>The vector.</returns>
        public virtual PgpUserAttributeSubpacketVector Generate()
        {
            return new PgpUserAttributeSubpacketVector(list.ToArray());
        }
    }
}
