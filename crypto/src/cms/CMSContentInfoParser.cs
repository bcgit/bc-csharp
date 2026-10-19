using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Cms
{
    // TODO[api] Make abstract
    /// <summary>Base class for parsers that read a CMS ContentInfo from a stream.</summary>
    public class CmsContentInfoParser
        : IDisposable
    {
        /// <summary>The parser for the ContentInfo.</summary>
        protected ContentInfoParser contentInfo;
        /// <summary>The stream being parsed.</summary>
        protected Stream data;

        /// <summary>Start parsing a ContentInfo from the stream.</summary>
        /// <param name="data">The stream to read from.</param>
        /// <exception cref="ArgumentNullException"><paramref name="data"/> is null.</exception>
        /// <exception cref="CmsException">The ContentInfo cannot be read.</exception>
        protected CmsContentInfoParser(Stream data)
        {
            this.data = data ?? throw new ArgumentNullException(nameof(data));

            try
            {
                Asn1StreamParser inStream = new Asn1StreamParser(data);

                this.contentInfo = new ContentInfoParser((Asn1SequenceParser)inStream.ReadObject());
            }
            catch (IOException e)
            {
                throw new CmsException("IOException reading content.", e);
            }
            catch (InvalidCastException e)
            {
                throw new CmsException("Unexpected object reading content.", e);
            }
        }

        [Obsolete("Dispose instead")]
        /// <summary>Dispose of the parser and its stream.</summary>
        public void Close()
        {
            Dispose();
        }

        #region IDisposable

        /// <summary>Dispose of the parser and its stream.</summary>
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        /// <summary>Dispose of the stream.</summary>
        /// <param name="disposing">true when called from <see cref="Dispose()"/>.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                data.Dispose();
            }
        }

        #endregion
    }
}
