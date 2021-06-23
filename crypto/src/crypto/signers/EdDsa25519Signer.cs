using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Signers
{
	public class EdDsa22519Signer : IDsa
	{
		private Ed25519Signer signer;

		public virtual string AlgorithmName => "EDDSA";

		public EdDsa22519Signer()
		{
			signer = new Ed25519Signer();
		}

		public virtual void Init(bool forSigning, ICipherParameters parameters)
		{
			signer.Init(forSigning, parameters);
		}

		public virtual BigInteger[] GenerateSignature(byte[] message)
		{
			signer.BlockUpdate(message, 0, message.Length);
			byte[] sigBytes = signer.GenerateSignature();
			byte[] rBytes = new byte[32];
			Array.Copy(sigBytes, rBytes, 32);
			byte[] sBytes = new byte[sigBytes.Length - 32];
			Array.Copy(sigBytes, 32, sBytes, 0, sigBytes.Length - 32);
			BigInteger r = new BigInteger(1, rBytes);
			BigInteger s = new BigInteger(1, sBytes);
			return new BigInteger[2] { r, s };
		}

		public virtual bool VerifySignature(byte[] message, BigInteger r, BigInteger s)
		{
			signer.BlockUpdate(message, 0, message.Length);
			byte[] rBytes = r.ToByteArrayUnsigned();
			byte[] sBytes = s.ToByteArrayUnsigned();
			byte[] sigBytes = new byte[rBytes.Length + sBytes.Length];
			Array.Copy(rBytes, sigBytes, rBytes.Length);
			Array.Copy(sBytes, 0, sigBytes, rBytes.Length, sBytes.Length);
			return signer.VerifySignature(sigBytes);
		}
	}
}
