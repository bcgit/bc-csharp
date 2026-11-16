using System.IO;

namespace Org.BouncyCastle.Utilities
{
    /// <summary>Interface for objects that can provide an encoded form of themselves.</summary>
    public interface IEncodable
    {
        /// <summary>Return a byte array representing the implementing object.</summary>
        /// <returns>An encoding of this object as a byte array.</returns>
        /// <exception cref="IOException"/>
        byte[] GetEncoded();

        // TODO[api]
        //void EncodeTo(Stream output);
    }
}
