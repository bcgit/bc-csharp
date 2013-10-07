using Org.BouncyCastle.Security;
using System;

namespace Org.BouncyCastle.Crypto.Tls {


public abstract class AbstractTlsContext : TlsContext
{
    private SecureRandom secureRandom;
    private SecurityParameters securityParameters;

    private ProtocolVersion clientVersion = null;
    private ProtocolVersion serverVersion = null;
    private TlsSession session = null;
    private object userObject = null;

    public AbstractTlsContext(SecureRandom secureRandom, SecurityParameters securityParameters)
    {
        this.secureRandom = secureRandom;
        this.securityParameters = securityParameters;
    }

    public SecureRandom SecureRandom
    {
        get
        {
            return secureRandom;
        }
    }

    public SecurityParameters SecurityParameters
    {
        get
        {
            return securityParameters;
        }
    }

    public ProtocolVersion ClientVersion
    {
        get
        {
            return clientVersion;
        }
        set
        {
            this.clientVersion = value;
        }
    }    

    public ProtocolVersion ServerVersion 
    {
        get
        {
            return serverVersion;
        }
        set
        {
            this.serverVersion = value;
        }
    }

    public TlsSession ResumableSession
    {
        get
        {        
            return session;
        }
        set 
        {
            this.session = value;
        }
    }
    
    public object UserObject
    {
        get
        {
            return userObject;
        }
        set
        {
            this.userObject = value;
        }
    }
    
    public byte[] ExportKeyingMaterial(string asciiLabel, byte[] context_value, int Length)
    {
        if (context_value != null && !TlsUtilities.IsValidUint16(context_value.Length))
        {
            throw new ArgumentException("'context_value' must have Length less than 2^16 (or be null)");
        }

        SecurityParameters sp = this.SecurityParameters;
        byte[] cr = sp.ClientRandom, sr = sp.ServerRandom;

        int seedLength = cr.Length + sr.Length;
        if (context_value != null)
        {
            seedLength += (2 + context_value.Length);
        }

        byte[] seed = new byte[seedLength];
        int seedPos = 0;

        Buffer.BlockCopy(cr, 0, seed, seedPos, cr.Length);
        seedPos += cr.Length;
        Buffer.BlockCopy(sr, 0, seed, seedPos, sr.Length);
        seedPos += sr.Length;
        if (context_value != null)
        {
            TlsUtilities.WriteUint16(context_value.Length, seed, seedPos);
            seedPos += 2;
            Buffer.BlockCopy(context_value, 0, seed, seedPos, context_value.Length);
            seedPos += context_value.Length;
        }

        if (seedPos != seedLength)
        {
            throw new InvalidOperationException("error in calculation of seed for export");
        }

        return TlsUtilities.PRF(this, sp.MasterSecret, asciiLabel, seed, Length);
    }

    #region TlsContext Members

    public abstract bool IsServer
    {
        get;
    }

    #endregion
}

}