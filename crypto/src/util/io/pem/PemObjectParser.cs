using System.IO;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
    /// <summary>Implemented by parsers that can create an object from a <see cref="PemObject"/>.</summary>
    public interface PemObjectParser
    {
        /// <param name="obj">
        /// A <see cref="PemObject"/>
        /// </param>
        /// <returns>
        /// An <see cref="object"/>
        /// </returns>
        /// <exception cref="IOException"></exception>
        object ParseObject(PemObject obj);
    }
}
