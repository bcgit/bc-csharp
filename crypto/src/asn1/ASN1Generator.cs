using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>
    /// Base class for the generators that write constructed ASN.1 objects to a stream piece by piece.
    /// </summary>
    public abstract class Asn1Generator
        : IDisposable
    {
        private Stream m_outStream;

        /// <summary>Create a new <see cref="Asn1Generator"/>.</summary>
        /// <param name="outStream">The output stream.</param>
        protected Asn1Generator(Stream outStream)
        {
            m_outStream = outStream ?? throw new ArgumentNullException(nameof(outStream));
        }

        protected abstract void Finish();

        /// <summary>Gets the out stream.</summary>
        protected Stream OutStream
        {
            get { return m_outStream ?? throw new InvalidOperationException(); }
        }

        public abstract void AddObject(Asn1Encodable obj);

        public abstract void AddObject(Asn1Object obj);

        /// <summary>Return the raw output stream.</summary>
        public abstract Stream GetRawOutputStream();

        #region IDisposable

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (m_outStream != null)
                {
                    Finish();
                    m_outStream = null;
                }
            }
        }

        #endregion

        internal static int InheritConstructedFlag(int intoTag, int fromTag)
        {
            if ((fromTag & Asn1Tags.Constructed) != 0)
                return intoTag | Asn1Tags.Constructed;

            return intoTag & ~Asn1Tags.Constructed;
        }
    }
}
