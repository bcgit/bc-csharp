using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    /// <summary>A holding class for a file of data to be processed.</summary>
    public class CmsProcessableFile
        : CmsTypedData, CmsReadable
    {
        private const int DefaultBufSize = 32 * 1024;

        private readonly DerObjectIdentifier m_type;
        private readonly FileInfo m_file;
        private readonly int m_bufSize;

        /// <summary>Create content of type <c>data</c> from a file.</summary>
        /// <param name="file">The file.</param>
        public CmsProcessableFile(FileInfo file)
            : this(file, DefaultBufSize)
        {
        }

        /// <summary>Create content of type <c>data</c> from a file, with the given buffer size.</summary>
        /// <param name="file">The file.</param>
        /// <param name="bufSize">The size of the buffer used when reading.</param>
        public CmsProcessableFile(FileInfo file, int bufSize)
            : this(CmsObjectIdentifiers.Data, file, bufSize)
        {
        }

        /// <summary>Create typed content from a file, with the given buffer size.</summary>
        /// <param name="type">The content type.</param>
        /// <param name="file">The file.</param>
        /// <param name="bufSize">The size of the buffer used when reading.</param>
        /// <exception cref="ArgumentNullException"><paramref name="type"/> is null.</exception>
        public CmsProcessableFile(DerObjectIdentifier type, FileInfo file, int bufSize)
        {
            m_type = type ?? throw new ArgumentNullException(nameof(type));
            m_file = file;
            m_bufSize = bufSize;
        }

        /// <summary>Return a new read-only stream over the file.</summary>
        public virtual Stream GetInputStream() =>
            new FileStream(m_file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, m_bufSize);

        /// <summary>Write the contents of the file to the stream.</summary>
        /// <param name="zOut">The stream to write to.</param>
        public virtual void Write(Stream zOut)
        {
            using (var inStr = m_file.OpenRead())
            {
                Streams.PipeAll(inStr, zOut, m_bufSize);
            }
        }

        /// <summary>Gets the content type.</summary>
        public DerObjectIdentifier ContentType => m_type;
    }
}
