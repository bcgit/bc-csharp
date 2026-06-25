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

        public CmsProcessableFile(FileInfo file)
            : this(file, DefaultBufSize)
        {
        }

        public CmsProcessableFile(FileInfo file, int bufSize)
            : this(CmsObjectIdentifiers.Data, file, bufSize)
        {
        }

        public CmsProcessableFile(DerObjectIdentifier type, FileInfo file, int bufSize)
        {
            m_type = type ?? throw new ArgumentNullException(nameof(type));
            m_file = file;
            m_bufSize = bufSize;
        }

        public virtual Stream GetInputStream() =>
            new FileStream(m_file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, m_bufSize);

        public virtual void Write(Stream zOut)
        {
            using (var inStr = m_file.OpenRead())
            {
                Streams.PipeAll(inStr, zOut, m_bufSize);
            }
        }

        public DerObjectIdentifier ContentType => m_type;
    }
}
