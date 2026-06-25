using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Cms
{
    internal class CmsTypedProcessable
        : CmsTypedData
    {
        private readonly DerObjectIdentifier m_contentType;
        private readonly CmsProcessable m_processable;

        internal CmsTypedProcessable(DerObjectIdentifier contentType, CmsProcessable processable)
        {
            m_contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
            m_processable = processable ?? throw new ArgumentNullException(nameof(processable));
        }

        public DerObjectIdentifier ContentType => m_contentType;

        public void Write(Stream outStream) => m_processable.Write(outStream);
    }
}
