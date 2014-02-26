using System;
using System.IO;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Tls
{
	internal class TlsPskKeyExchange
		: TlsKeyExchange
	{
		protected TlsClientContext context;
		protected KeyExchangeAlgorithm keyExchange;
		protected TlsPskIdentity pskIdentity;

		protected byte[] psk_identity_hint = null;

		protected DHPublicKeyParameters dhAgreeServerPublicKey = null;
		protected DHPrivateKeyParameters dhAgreeClientPrivateKey = null;

		protected RsaKeyParameters rsaServerPublicKey = null;
		protected byte[] premasterSecret;

		internal TlsPskKeyExchange(TlsClientContext context, KeyExchangeAlgorithm keyExchange,
			TlsPskIdentity pskIdentity)
		{
			switch (keyExchange)
			{
				case KeyExchangeAlgorithm.PSK:
				case KeyExchangeAlgorithm.RSA_PSK:
				case KeyExchangeAlgorithm.DHE_PSK:
					break;
				default:
					throw new ArgumentException("unsupported key exchange algorithm", "keyExchange");
			}

			this.context = context;
			this.keyExchange = keyExchange;
			this.pskIdentity = pskIdentity;
		}

		public virtual void SkipServerCertificate()
		{
			// OK
		}

		public virtual void ProcessServerCertificate(Certificate serverCertificate)
		{
			throw new TlsFatalAlert(AlertDescription.unexpected_message);
		}

		public virtual void SkipServerKeyExchange()
		{
			this.psk_identity_hint = new byte[0];
		}

		public virtual void ProcessServerKeyExchange(Stream input)
		{
			this.psk_identity_hint = TlsUtilities.ReadOpaque16(input);

			if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
			{
				byte[] pBytes = TlsUtilities.ReadOpaque16(input);
				byte[] gBytes = TlsUtilities.ReadOpaque16(input);
				byte[] YsBytes = TlsUtilities.ReadOpaque16(input);

				BigInteger p = new BigInteger(1, pBytes);
				BigInteger g = new BigInteger(1, gBytes);
				BigInteger Ys = new BigInteger(1, YsBytes);
				
				this.dhAgreeServerPublicKey = TlsDHUtilities.ValidateDHPublicKey(
					new DHPublicKeyParameters(Ys, new DHParameters(p, g)));
			}
			else if (this.psk_identity_hint.Length == 0)
			{
				// TODO Should we enforce that this message should have been skipped if hint is empty?
				//throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
		}

		public virtual void ValidateCertificateRequest(CertificateRequest certificateRequest)
		{
			throw new TlsFatalAlert(AlertDescription.unexpected_message);
		}

		public virtual void SkipClientCredentials()
		{
			// OK
		}

		public virtual void ProcessClientCredentials(TlsCredentials clientCredentials)
		{
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		public virtual void GenerateClientKeyExchange(Stream output)
		{
			if (psk_identity_hint == null || psk_identity_hint.Length == 0)
			{
				pskIdentity.SkipIdentityHint();
			}
			else
			{
				pskIdentity.NotifyIdentityHint(psk_identity_hint);
			}

			byte[] psk_identity = pskIdentity.GetPskIdentity();

			TlsUtilities.WriteOpaque16(psk_identity, output);

			if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
			{
				this.premasterSecret = TlsRsaUtilities.GenerateEncryptedPreMasterSecret(
					context.SecureRandom, this.rsaServerPublicKey, output);
			}
			else if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
			{
				this.dhAgreeClientPrivateKey = TlsDHUtilities.GenerateEphemeralClientKeyExchange(
					context.SecureRandom, this.dhAgreeServerPublicKey.Parameters, output);
			}
		}

		public virtual byte[] GeneratePremasterSecret()
		{
			byte[] psk = pskIdentity.GetPsk();
			byte[] other_secret = GenerateOtherSecret(psk.Length);

			MemoryStream buf = new MemoryStream(4 + other_secret.Length + psk.Length);
			TlsUtilities.WriteOpaque16(other_secret, buf);
			TlsUtilities.WriteOpaque16(psk, buf);
			return buf.ToArray();
		}

		protected virtual byte[] GenerateOtherSecret(int pskLength)
		{
			if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
			{
				return TlsDHUtilities.CalculateDHBasicAgreement(dhAgreeServerPublicKey, dhAgreeClientPrivateKey);
			}

			if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
			{
				return this.premasterSecret;
			}

			return new byte[pskLength];
		}
	}
}
