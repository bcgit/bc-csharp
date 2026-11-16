using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Content read from a stream, which can only be used once.</summary>
    public class CmsProcessableInputStream
        : CmsProcessable, CmsReadable
    {
        private readonly Stream m_input;

        private bool used = false;

        /// <summary>Create content from a stream.</summary>
        /// <param name="input">The stream to read the content from.</param>
        public CmsProcessableInputStream(Stream input)
        {
            m_input = input;
        }

        /// <summary>Return the stream; this can only be done once.</summary>
        /// <exception cref="InvalidOperationException">The content has already been used.</exception>
        public virtual Stream GetInputStream()
        {
            CheckSingleUsage();

            return m_input;
        }

        /// <summary>Copy the content to the stream, then dispose of the input stream; this can only be done once.
        /// </summary>
        /// <param name="output">The stream to write to.</param>
        /// <exception cref="InvalidOperationException">The content has already been used.</exception>
        public virtual void Write(Stream output)
        {
            CheckSingleUsage();

            using (m_input)
            {
                Streams.PipeAll(m_input, output);
            }
        }

        /// <summary>Mark the content as used.</summary>
        /// <exception cref="InvalidOperationException">The content has already been used.</exception>
        protected virtual void CheckSingleUsage()
        {
            lock (this)
            {
                if (used)
                    throw new InvalidOperationException("CmsProcessableInputStream can only be used once");

                used = true;
            }
        }
    }
}
