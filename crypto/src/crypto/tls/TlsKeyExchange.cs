using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
	/// <summary>
	/// A generic interface for key exchange implementations in TLS 1.0.
	/// </summary>
	public interface TlsKeyExchange
	{
		/// <exception cref="IOException"/>
        void Init(TlsContext context);

        void SkipServerCredentials();

        void ProcessServerCredentials(TlsCredentials serverCredentials);

		/// <exception cref="IOException"/>
		void ProcessServerCertificate(Certificate serverCertificate);

        bool  RequiresServerKeyExchange { get; } 

        byte[] GenerateServerKeyExchange();
        
		/// <exception cref="IOException"/>
		void SkipServerKeyExchange();

		/// <exception cref="IOException"/>
		void ProcessServerKeyExchange(Stream input);

		/// <exception cref="IOException"/>
		void ValidateCertificateRequest(CertificateRequest certificateRequest);

		/// <exception cref="IOException"/>
		void SkipClientCredentials();

		/// <exception cref="IOException"/>
		void ProcessClientCredentials(TlsCredentials clientCredentials);
		
        void ProcessClientCertificate(Certificate clientCertificate);

		void GenerateClientKeyExchange(Stream output);

        void ProcessClientKeyExchange(Stream input);

		/// <exception cref="IOException"/>
		byte[] GeneratePremasterSecret();
	}
}
