using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public abstract class Asn1Generator
        : IDisposable
    {
		private Stream m_outStream;

		protected Asn1Generator(Stream outStream)
        {
            m_outStream = outStream ?? throw new ArgumentNullException(nameof(outStream));
        }

        protected abstract void Finish();

		protected Stream OutStream
		{
			get { return m_outStream ?? throw new InvalidOperationException(); }
		}

		public abstract void AddObject(Asn1Encodable obj);

        public abstract void AddObject(Asn1Object obj);

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
