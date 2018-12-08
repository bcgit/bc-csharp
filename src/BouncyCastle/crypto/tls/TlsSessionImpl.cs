using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    internal class TlsSessionImpl
        :   TlsSession
    {
        internal readonly byte[] mSessionID;
        internal readonly SessionParameters mSessionParameters;
        internal bool mResumable;

        internal TlsSessionImpl(byte[] sessionID, SessionParameters sessionParameters)
        {
            if (sessionID == null)
                throw new ArgumentNullException("sessionID");
            if (sessionID.Length > 32)
                throw new ArgumentException("cannot be longer than 32 bytes", "sessionID");

            this.mSessionID = Arrays.Clone(sessionID);
            this.mSessionParameters = sessionParameters;
            this.mResumable = sessionID.Length > 0
                && null != sessionParameters
                && sessionParameters.IsExtendedMasterSecret;
        }

        public virtual SessionParameters ExportSessionParameters()
        {
            lock (this)
            {
                return this.mSessionParameters == null ? null : this.mSessionParameters.Copy();
            }
        }

        public virtual byte[] SessionID
        {
            get { lock (this) return mSessionID; }
        }

        public virtual void Invalidate()
        {
            lock (this) this.mResumable = false;
        }

        public virtual bool IsResumable
        {
            get { lock (this) return mResumable; }
        }
    }
}
