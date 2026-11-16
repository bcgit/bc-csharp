using System;
using System.IO;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Content that can be written to a stream for processing, for example for signing or enveloping.
    /// </summary>
    public interface CmsProcessable
    {
        /// <summary>
        /// Generic routine to copy out the data we want processed.
        /// </summary>
        /// <remarks>
        /// This routine may be called multiple times.
        /// </remarks>
        /// <param name="outStream">The stream to copy the data to.</param>
        void Write(Stream outStream);
    }
}
