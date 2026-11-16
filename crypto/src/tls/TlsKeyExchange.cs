using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>A generic interface for key exchange implementations in (D)TLS.</summary>
    public interface TlsKeyExchange
    {
        /// <summary>Initialise the key exchange with its context.</summary>
        /// <param name="context">The TLS context.</param>
        void Init(TlsContext context);

        /// <exception cref="IOException"/>
        void SkipServerCredentials();

        /// <exception cref="IOException"/>
        void ProcessServerCredentials(TlsCredentials serverCredentials);

        /// <exception cref="IOException"/>
        void ProcessServerCertificate(Certificate serverCertificate);

        /// <summary>Gets the requires server key exchange.</summary>
        bool RequiresServerKeyExchange { get; }

        /// <exception cref="IOException"/>
        byte[] GenerateServerKeyExchange();

        /// <exception cref="IOException"/>
        void SkipServerKeyExchange();

        /// <exception cref="IOException"/>
        void ProcessServerKeyExchange(Stream input);

        /// <summary>Return the client certificate types.</summary>
        short[] GetClientCertificateTypes();

        /// <exception cref="IOException"/>
        void SkipClientCredentials();

        /// <exception cref="IOException"/>
        void ProcessClientCredentials(TlsCredentials clientCredentials);

        /// <exception cref="IOException"/>
        void ProcessClientCertificate(Certificate clientCertificate);

        /// <exception cref="IOException"/>
        void GenerateClientKeyExchange(Stream output);

        /// <exception cref="IOException"/>
        void ProcessClientKeyExchange(Stream input);

        /// <summary>Gets the requires certificate verify.</summary>
        bool RequiresCertificateVerify { get; }

        /// <exception cref="IOException"/>
        TlsSecret GeneratePreMasterSecret();
    }
}
