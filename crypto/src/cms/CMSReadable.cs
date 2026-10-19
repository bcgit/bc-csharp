using System.IO;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Content that can be read from a stream.</summary>
    public interface CmsReadable
    {
        /// <summary>Return a stream to read the content from.</summary>
        Stream GetInputStream();
    }
}
