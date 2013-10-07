using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Tls
{
	public interface TlsSigner
	{
        void Init(TlsContext context);

        byte[] GenerateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1);

        bool VerifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] md5AndSha1);

        ISigner CreateSigner(AsymmetricKeyParameter privateKey);

		ISigner CreateVerifyer(AsymmetricKeyParameter publicKey);

		bool IsValidPublicKey(AsymmetricKeyParameter publicKey);
	}
}
