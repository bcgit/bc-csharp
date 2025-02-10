using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A one pass signature object.</remarks>
    public class PgpOnePassSignature
    {
        private static OnePassSignaturePacket Cast(Packet packet)
        {
            if (packet is OnePassSignaturePacket onePassSignaturePacket)
                return onePassSignaturePacket;

            throw new IOException("unexpected packet in stream: " + packet);
        }

        private readonly OnePassSignaturePacket sigPack;
        private readonly int signatureType;
		private ISigner sig;
		private byte lastb;

		internal PgpOnePassSignature(
            BcpgInputStream bcpgInput)
            : this(Cast(bcpgInput.ReadPacket()))
        {
        }

		internal PgpOnePassSignature(
            OnePassSignaturePacket sigPack)
        {
            this.sigPack = sigPack;
            this.signatureType = sigPack.SignatureType;
        }

		/// <summary>Initialise the signature object for verification.</summary>
        public void InitVerify(PgpPublicKey pubKey)
        {
			lastb = 0;
            AsymmetricKeyParameter key = pubKey.GetKey();

            try
			{
				sig = PgpUtilities.CreateSigner(sigPack.KeyAlgorithm, sigPack.HashAlgorithm, key);
			}
			catch (Exception e)
			{
				throw new PgpException("can't set up signature object.",  e);
			}

			try
            {
                sig.Init(false, key);
                if (sigPack.Version == OnePassSignaturePacket.Version6)
                {
                    byte[] salt = sigPack.GetSignatureSalt();
                    sig.BlockUpdate(salt, 0, salt.Length);
                }
            }
			catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }
        }

		public void Update(byte b)
        {
			if (signatureType == PgpSignature.CanonicalTextDocument)
			{
				DoCanonicalUpdateByte(b);
			}
			else
			{
				sig.Update(b);
			}
        }

		private void DoCanonicalUpdateByte(byte b)
		{
			if (b == '\r')
			{
				DoUpdateCRLF();
			}
			else if (b == '\n')
			{
				if (lastb != '\r')
				{
					DoUpdateCRLF();
				}
			}
			else
			{
				sig.Update(b);
			}

			lastb = b;
		}

		private void DoUpdateCRLF()
		{
			sig.Update((byte)'\r');
			sig.Update((byte)'\n');
		}

		public void Update(params byte[] bytes)
        {
            Update(bytes, 0, bytes.Length);
        }

        public void Update(byte[] bytes, int off, int length)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Update(bytes.AsSpan(off, length));
#else
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                int finish = off + length;

                for (int i = off; i != finish; i++)
                {
                    DoCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.BlockUpdate(bytes, off, length);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Update(ReadOnlySpan<byte> input)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                for (int i = 0; i < input.Length; ++i)
                {
                    DoCanonicalUpdateByte(input[i]);
                }
            }
            else
            {
                sig.BlockUpdate(input);
            }
        }
#endif

        /// <summary>Verify the calculated signature against the passed in PgpSignature.</summary>
        public bool Verify(PgpSignature pgpSig)
        {
            return Verify(pgpSig, Array.Empty<byte>());
        }

        public bool Verify(PgpSignature pgpSig, byte[] additionalMetadata)
        {
            // the versions of the Signature and the One-Pass Signature must be aligned as specified in
            // https://www.rfc-editor.org/rfc/rfc9580#signed-message-versions
            if (pgpSig.Version == SignaturePacket.Version6 && sigPack.Version != OnePassSignaturePacket.Version6)
            {
                return false;
            }
            if (pgpSig.Version < SignaturePacket.Version6 && sigPack.Version != OnePassSignaturePacket.Version3)
            {
                return false;
            }
            // Additional metadata for v5 signatures
            byte[] trailer = pgpSig.GetSignatureTrailer(additionalMetadata);

			sig.BlockUpdate(trailer, 0, trailer.Length);

			return sig.VerifySignature(pgpSig.GetSignature());
        }

        public long KeyId
        {
			get { return sigPack.KeyId; }
        }

        public int Version
        {
            get { return sigPack.Version; }
        }

        public int SignatureType
        {
            get { return sigPack.SignatureType; }
        }

		public HashAlgorithmTag HashAlgorithm
		{
			get { return sigPack.HashAlgorithm; }
		}

		public PublicKeyAlgorithmTag KeyAlgorithm
		{
			get { return sigPack.KeyAlgorithm; }
		}

        public byte[] GetSignatureSalt()
        {
            return sigPack.GetSignatureSalt();
        }

        public byte[] GetFingerprint()
        {
            return sigPack.GetFingerprint();
        }

        public byte[] GetEncoded()
        {
            var bOut = new MemoryStream();

            Encode(bOut);

            return bOut.ToArray();
        }

		public void Encode(Stream outStr)
        {
            BcpgOutputStream.Wrap(outStr).WritePacket(sigPack);
        }
    }
}
