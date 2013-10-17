using System;
using Org.BouncyCastle.Utilities;


namespace Org.BouncyCastle.Crypto.Tls {


class TlsSessionImpl : TlsSession
{
    readonly byte[] sessionID;
    SessionParameters sessionParameters;
    private object _lock = new object(); 

    public TlsSessionImpl(byte[] sessionID, SessionParameters sessionParameters)
    {
        if (sessionID == null)
        {
            throw new ArgumentException("'sessionID' cannot be null");
        }

        if (sessionID.Length < 1 || sessionID.Length > 32)
        {
            throw new ArgumentException("'sessionID' must have length between 1 and 32 bytes, inclusive");
        }

        this.sessionID = Arrays.Clone(sessionID);
        this.sessionParameters = sessionParameters;
    }

    public SessionParameters ExportSessionParameters()
    {
        lock(_lock) 
        {
            return this.sessionParameters == null ? null : this.sessionParameters.Copy();
        }
    }

    public byte[] GetSessionID()
    {
        lock(_lock) 
        {
            return sessionID;
        }
    }

    public void Invalidate()
    {
        lock (_lock)
        {
            if (this.sessionParameters != null)
            {
                this.sessionParameters.Clear();
                this.sessionParameters = null;
            }
        }
    }

    public bool IsResumable
    {
        get
        {
            lock (_lock)
            {
                return this.sessionParameters != null;
            }
        }
    }
}

}