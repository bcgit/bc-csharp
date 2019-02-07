using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
	public class DsaDigestSigner
		: ISigner
	{
        private readonly IDsa dsa;
        private readonly IDigest digest;
        private readonly IDsaEncoding encoding;
        private bool forSigning;

		public DsaDigestSigner(
			IDsa	dsa,
			IDigest	digest)
		{
            this.dsa = dsa;
            this.digest = digest;
            this.encoding = StandardDsaEncoding.Instance;
		}

        public DsaDigestSigner(
            IDsaExt dsa,
            IDigest digest,
            IDsaEncoding encoding)
        {
            this.dsa = dsa;
            this.digest = digest;
            this.encoding = encoding;
        }

		public virtual string AlgorithmName
		{
			get { return digest.AlgorithmName + "with" + dsa.AlgorithmName; }
		}

        public virtual void Init(
			bool forSigning,
			ICipherParameters parameters)
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

			dsa.Init(forSigning, parameters);
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

            BigInteger[] sig = dsa.GenerateSignature(hash);

            try
            {
                return encoding.Encode(GetOrder(), sig[0], sig[1]);
            }
            catch (Exception)
            {
                throw new InvalidOperationException("unable to encode signature");
            }
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
                BigInteger[] sig = encoding.Decode(GetOrder(), signature);

                return dsa.VerifySignature(hash, sig[0], sig[1]);
            }
            catch (Exception)
            {
                return false;
            }
		}

		/// <summary>Reset the internal state</summary>
        public virtual void Reset()
		{
			digest.Reset();
		}

        protected virtual BigInteger GetOrder()
        {
            return dsa is IDsaExt ? ((IDsaExt)dsa).Order : null;
        }
	}
}
