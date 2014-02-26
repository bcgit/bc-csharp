using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Tls
{
	internal class TlsRsaSigner
    	: TlsSigner
	{
		public virtual byte[] CalculateRawSignature(SecureRandom random,
			AsymmetricKeyParameter privateKey, byte[] md5andsha1)
		{
			ISigner s = MakeSigner(new NullDigest(), true, new ParametersWithRandom(privateKey, random));
			s.BlockUpdate(md5andsha1, 0, md5andsha1.Length);
			return s.GenerateSignature();
		}

		public virtual bool VerifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey,
			byte[] md5andsha1)
		{
			ISigner s = MakeSigner(new NullDigest(), false, publicKey);
			s.BlockUpdate(md5andsha1, 0, md5andsha1.Length);
			return s.VerifySignature(sigBytes);
		}

		public virtual ISigner CreateSigner(SecureRandom random, AsymmetricKeyParameter privateKey)
		{
			return MakeSigner(new CombinedHash(), true, new ParametersWithRandom(privateKey, random));
		}

        public virtual ISigner CreateVerifyer(AsymmetricKeyParameter publicKey)
		{
			return MakeSigner(new CombinedHash(), false, publicKey);
		}

		public virtual bool IsValidPublicKey(AsymmetricKeyParameter publicKey)
		{
			return publicKey is RsaKeyParameters && !publicKey.IsPrivate;
		}

		protected virtual ISigner MakeSigner(IDigest d, bool forSigning, ICipherParameters cp)
		{
			ISigner s = new GenericSigner(new Pkcs1Encoding(new RsaBlindedEngine()), d);
			s.Init(forSigning, cp);
			return s;
		}
	}
}
