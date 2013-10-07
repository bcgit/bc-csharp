using System;
using Org.BouncyCastle.Utilities;
using System.IO;
using System.Collections;
namespace Org.BouncyCastle.Crypto.Tls {

public sealed class SessionParameters
{
    public sealed class Builder
    {
        private CipherSuite cipherSuite = CipherSuite.UNASSINGED;
        private CompressionMethod compressionAlgorithm = CompressionMethod.NULL;
        private byte[] masterSecret = null;
        private Certificate peerCertificate = null;
        private byte[] encodedServerExtensions = null;

        public Builder()
        {
        }

        public SessionParameters Build()
        {
            Validate(this.cipherSuite >= 0, "cipherSuite");
            Validate(this.compressionAlgorithm >= 0, "compressionAlgorithm");
            Validate(this.masterSecret != null, "masterSecret");
            return new SessionParameters(cipherSuite, compressionAlgorithm, masterSecret, peerCertificate,
                encodedServerExtensions);
        }

        public Builder SetCipherSuite(CipherSuite cipherSuite)
        {
            this.cipherSuite = cipherSuite;
            return this;
        }

        public Builder SetCompressionAlgorithm(CompressionMethod compressionAlgorithm)
        {
            this.compressionAlgorithm = compressionAlgorithm;
            return this;
        }

        public Builder SetMasterSecret(byte[] masterSecret)
        {
            this.masterSecret = masterSecret;
            return this;
        }

        public Builder SetPeerCertificate(Certificate peerCertificate)
        {
            this.peerCertificate = peerCertificate;
            return this;
        }

        public Builder SetServerExtensions(IDictionary serverExtensions)
        {
            if (serverExtensions == null)
            {
                encodedServerExtensions = null;
            }
            else
            {
                MemoryStream buf = new MemoryStream();
                TlsProtocol.WriteExtensions(buf, serverExtensions);
                encodedServerExtensions = buf.ToArray();
            }
            return this;
        }

        private void Validate(bool condition, String parameter)
        {
            if (!condition)
            {
                throw new InvalidOperationException("Required session parameter '" + parameter + "' not configured");
            }
        }
    }

    private readonly CipherSuite cipherSuite;
    private readonly CompressionMethod compressionAlgorithm;
    private readonly byte[] masterSecret;
    private readonly Certificate peerCertificate;
    private readonly byte[] encodedServerExtensions;

    private SessionParameters(CipherSuite cipherSuite, CompressionMethod compressionAlgorithm, byte[] masterSecret,
        Certificate peerCertificate, byte[] encodedServerExtensions)
    {
        this.cipherSuite = cipherSuite;
        this.compressionAlgorithm = compressionAlgorithm;
        this.masterSecret = Arrays.Clone(masterSecret);
        this.peerCertificate = peerCertificate;
        this.encodedServerExtensions = encodedServerExtensions;
    }

    public void Clear()
    {
        if (this.masterSecret != null)
        {
            Arrays.Fill(this.masterSecret, (byte)0);
        }
    }

    public SessionParameters Copy()
    {
        return new SessionParameters(cipherSuite, compressionAlgorithm, masterSecret, peerCertificate,
            encodedServerExtensions);
    }

    public CipherSuite CipherSuite
    {
        get
        {
            return cipherSuite;
        }
    }

    public CompressionMethod CompressionAlgorithm
    {
        get
        {
            return compressionAlgorithm;
        }
    }

    public byte[] MasterSecret
    {
        get
        {
            return masterSecret;
        }
    }

    public Certificate PeerCertificate
    {
        get
        {
            return peerCertificate;
        }
    }

    public Hashtable ReadServerExtensions() 
    {
        if (encodedServerExtensions == null)
        {
            return null;
        }

        var buf = new MemoryStream(encodedServerExtensions);
        return TlsProtocol.ReadExtensions(buf);
    }
}

}