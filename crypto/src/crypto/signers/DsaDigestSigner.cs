using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class DsaDigestSigner
		: ISigner
	{
		private readonly IDigest digest;
		private readonly IDsa dsaSigner;
		private bool forSigning;
        private bool useDerEncoding;

		public DsaDigestSigner(
			IDsa	signer,
			IDigest	digest,
            bool useDerEncoding = true)
		{
			this.digest = digest;
			this.dsaSigner = signer;
            this.useDerEncoding = useDerEncoding;
		}

		public virtual string AlgorithmName
		{
			get { return digest.AlgorithmName + "with" + dsaSigner.AlgorithmName; }
		}

        public virtual void Init(
			bool							forSigning,
			ICipherParameters	parameters)
		{
			this.forSigning = forSigning;

			AsymmetricKeyParameter k;

			if (parameters is ParametersWithRandom)
			{
				k = (AsymmetricKeyParameter)((ParametersWithRandom)parameters).Parameters;
			}
			else
			{
				k = (AsymmetricKeyParameter)parameters;
			}

			if (forSigning && !k.IsPrivate)
				throw new InvalidKeyException("Signing Requires Private Key.");

			if (!forSigning && k.IsPrivate)
				throw new InvalidKeyException("Verification Requires Public Key.");

			Reset();

			dsaSigner.Init(forSigning, parameters);
		}

		/**
		 * update the internal digest with the byte b
		 */
        public virtual void Update(
			byte input)
		{
			digest.Update(input);
		}

		/**
		 * update the internal digest with the byte array in
		 */
        public virtual void BlockUpdate(
			byte[]	input,
			int			inOff,
			int			length)
		{
			digest.BlockUpdate(input, inOff, length);
		}

		/**
		 * Generate a signature for the message we've been loaded with using
		 * the key we were initialised with.
     */
        public virtual byte[] GenerateSignature()
		{
			if (!forSigning)
				throw new InvalidOperationException("DSADigestSigner not initialised for signature generation.");

			byte[] hash = new byte[digest.GetDigestSize()];
			digest.DoFinal(hash, 0);

			BigInteger[] sig = dsaSigner.GenerateSignature(hash);

			return EncodeSignature(sig[0], sig[1]);
		}

		/// <returns>true if the internal state represents the signature described in the passed in array.</returns>
        public virtual bool VerifySignature(
			byte[] signature)
		{
			if (forSigning)
				throw new InvalidOperationException("DSADigestSigner not initialised for verification");

			byte[] hash = new byte[digest.GetDigestSize()];
			digest.DoFinal(hash, 0);

			try
			{
				BigInteger[] sig = DecodeSignature(signature);
				return dsaSigner.VerifySignature(hash, sig[0], sig[1]);
			}
			catch (IOException)
			{
				return false;
			}
		}

		/// <summary>Reset the internal state</summary>
        public virtual void Reset()
		{
			digest.Reset();
		}

        private byte[] EncodeSignature(
            BigInteger r,
            BigInteger s)
        {
            if (useDerEncoding)
            {
                return DerEncode(r, s);
            } else
            {
                return PlainEncode(r, s);
            }

        }

        private BigInteger[] DecodeSignature(byte[] rawSignature)
        {
            if (useDerEncoding)
            {
                return DerDecode(rawSignature);
            } else
            {
                return PlainDecode(rawSignature);
            }
            
        }

        private byte[] DerEncode(
			BigInteger	r,
			BigInteger	s)
		{
			return new DerSequence(new DerInteger(r), new DerInteger(s)).GetDerEncoded();
		}

		private BigInteger[] DerDecode(
			byte[] encoding)
		{
			Asn1Sequence s = (Asn1Sequence) Asn1Object.FromByteArray(encoding);

			return new BigInteger[]
			{
				((DerInteger) s[0]).Value,
				((DerInteger) s[1]).Value
			};
		}

        private byte[] PlainEncode(
            BigInteger r,
            BigInteger s)
        {
            var rBytes = r.ToByteArray();
            var sBytes = s.ToByteArray();

            var encodedSignature = new byte[rBytes.Length + sBytes.Length];
            Array.Copy(rBytes, encodedSignature, rBytes.Length);
            Array.Copy(sBytes, 0, encodedSignature, rBytes.Length, sBytes.Length);

            return encodedSignature;
        }

        private BigInteger[] PlainDecode(
            byte[] rawSignature)
        {
            var partLength = rawSignature.Length / 2;

            // Add extra 0 in front to avoid negative numbers
            var R = new byte[1 + partLength];
            var S = new byte[1 + partLength];

            Array.Copy(rawSignature, 0, R, 1, partLength);
            Array.Copy(rawSignature, partLength, S, 1, partLength);

            return new BigInteger[] { new BigInteger(R), new BigInteger(S) };
        }
	}
}
