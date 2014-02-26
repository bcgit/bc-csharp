using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
	/// <summary>
	/// A generic TLS 1.0 block cipher. This can be used for AES or 3DES for example.
	/// </summary>
	public class TlsBlockCipher
        : TlsCipher
	{
		protected TlsClientContext context;

        protected IBlockCipher encryptCipher;
        protected IBlockCipher decryptCipher;

        protected TlsMac wMac;
        protected TlsMac rMac;

		public virtual TlsMac WriteMac
		{
            get { return wMac; }
		}

		public virtual TlsMac ReadMac
		{
            get { return rMac; }
		}

		public TlsBlockCipher(TlsClientContext context, IBlockCipher encryptCipher,
			IBlockCipher decryptCipher, IDigest writeDigest, IDigest readDigest, int cipherKeySize)
		{
			this.context = context;
			this.encryptCipher = encryptCipher;
			this.decryptCipher = decryptCipher;

			int prfSize = (2 * cipherKeySize) + writeDigest.GetDigestSize()
				+ readDigest.GetDigestSize() + encryptCipher.GetBlockSize()
				+ decryptCipher.GetBlockSize();

			SecurityParameters securityParameters = context.SecurityParameters;

			byte[] keyBlock = TlsUtilities.PRF(securityParameters.masterSecret, "key expansion",
				TlsUtilities.Concat(securityParameters.serverRandom, securityParameters.clientRandom),
				prfSize);

			int offset = 0;

			// Init MACs
			wMac = CreateTlsMac(writeDigest, keyBlock, ref offset);
            rMac = CreateTlsMac(readDigest, keyBlock, ref offset);

			// Build keys
			KeyParameter encryptKey = CreateKeyParameter(keyBlock, ref offset, cipherKeySize);
			KeyParameter decryptKey = CreateKeyParameter(keyBlock, ref offset, cipherKeySize);

			// Add IVs
			ParametersWithIV encryptParams = CreateParametersWithIV(encryptKey,
				keyBlock, ref offset, encryptCipher.GetBlockSize());
			ParametersWithIV decryptParams = CreateParametersWithIV(decryptKey,
				keyBlock, ref offset, decryptCipher.GetBlockSize());

			if (offset != prfSize)
				throw new TlsFatalAlert(AlertDescription.internal_error);

			// Init Ciphers
			encryptCipher.Init(true, encryptParams);
			decryptCipher.Init(false, decryptParams);
		}

        protected virtual TlsMac CreateTlsMac(IDigest digest, byte[] buf, ref int off)
		{
			int len = digest.GetDigestSize();
			TlsMac mac = new TlsMac(digest, buf, off, len);
			off += len;
			return mac;
		}

        protected virtual KeyParameter CreateKeyParameter(byte[] buf, ref int off, int len)
		{
			KeyParameter key = new KeyParameter(buf, off, len);
			off += len;
			return key;
		}

        protected virtual ParametersWithIV CreateParametersWithIV(KeyParameter key,
			byte[] buf, ref int off, int len)
		{
			ParametersWithIV ivParams = new ParametersWithIV(key, buf, off, len);
			off += len;
			return ivParams;
		}

		public virtual byte[] EncodePlaintext(ContentType type, byte[] plaintext, int offset, int len)
		{
			int blocksize = encryptCipher.GetBlockSize();

			// Add a random number of extra blocks worth of padding
            int minPaddingSize = blocksize - ((len + wMac.Size + 1) % blocksize);
			int maxExtraPadBlocks = (255 - minPaddingSize) / blocksize;
			int actualExtraPadBlocks = ChooseExtraPadBlocks(context.SecureRandom, maxExtraPadBlocks);
			int paddingsize = minPaddingSize + (actualExtraPadBlocks * blocksize);

            int totalsize = len + wMac.Size + paddingsize + 1;
			byte[] outbuf = new byte[totalsize];
			Array.Copy(plaintext, offset, outbuf, 0, len);
            byte[] mac = wMac.CalculateMac(type, plaintext, offset, len);
			Array.Copy(mac, 0, outbuf, len, mac.Length);
			int paddoffset = len + mac.Length;
			for (int i = 0; i <= paddingsize; i++)
			{
				outbuf[i + paddoffset] = (byte)paddingsize;
			}
			for (int i = 0; i < totalsize; i += blocksize)
			{
				encryptCipher.ProcessBlock(outbuf, i, outbuf, i);
			}
			return outbuf;
		}

        public virtual byte[] DecodeCiphertext(ContentType type, byte[] ciphertext, int offset, int len)
		{
			// TODO TLS 1.1 (RFC 4346) introduces an explicit IV

            int minLength = rMac.Size + 1;
			int blocksize = decryptCipher.GetBlockSize();
			bool decrypterror = false;

			/*
			* ciphertext must be at least (macsize + 1) bytes long
			*/
			if (len < minLength)
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}

			/*
			* ciphertext must be a multiple of blocksize
			*/
			if (len % blocksize != 0)
			{
				throw new TlsFatalAlert(AlertDescription.decryption_failed);
			}

			/*
			* Decrypt all the ciphertext using the blockcipher
			*/
			for (int i = 0; i < len; i += blocksize)
			{
				decryptCipher.ProcessBlock(ciphertext, i + offset, ciphertext, i + offset);
			}

			/*
			* Check if padding is correct
			*/
			int lastByteOffset = offset + len - 1;

			byte paddingsizebyte = ciphertext[lastByteOffset];

			int paddingsize = paddingsizebyte;

			int maxPaddingSize = len - minLength;
			if (paddingsize > maxPaddingSize)
			{
				decrypterror = true;
				paddingsize = 0;
			}
			else
			{
				/*
				* Now, check all the padding-bytes (constant-time comparison).
				*/
				byte diff = 0;
				for (int i = lastByteOffset - paddingsize; i < lastByteOffset; ++i)
				{
					diff |= (byte)(ciphertext[i] ^ paddingsizebyte);
				}
				if (diff != 0)
				{
					/* Wrong padding */
					decrypterror = true;
					paddingsize = 0;
				}
			}

			/*
			* We now don't care if padding verification has failed or not, we will calculate
			* the mac to give an attacker no kind of timing profile he can use to find out if
			* mac verification failed or padding verification failed.
			*/
			int plaintextlength = len - minLength - paddingsize;
            byte[] calculatedMac = rMac.CalculateMac(type, ciphertext, offset, plaintextlength);

			/*
			* Check all bytes in the mac (constant-time comparison).
			*/
			byte[] decryptedMac = new byte[calculatedMac.Length];
			Array.Copy(ciphertext, offset + plaintextlength, decryptedMac, 0, calculatedMac.Length);

			if (!Arrays.ConstantTimeAreEqual(calculatedMac, decryptedMac))
			{
				decrypterror = true;
			}

			/*
			* Now, it is safe to fail.
			*/
			if (decrypterror)
			{
				throw new TlsFatalAlert(AlertDescription.bad_record_mac);
			}

			byte[] plaintext = new byte[plaintextlength];
			Array.Copy(ciphertext, offset, plaintext, 0, plaintextlength);
			return plaintext;
		}

		protected virtual int ChooseExtraPadBlocks(SecureRandom r, int max)
		{
//			return r.NextInt(max + 1);

			uint x = (uint)r.NextInt();
			int n = LowestBitSet(x);
			return System.Math.Min(n, max);
		}

        private int LowestBitSet(uint x)
		{
			if (x == 0)
			{
				return 32;
			}

			int n = 0;
			while ((x & 1) == 0)
			{
				++n;
				x >>= 1;
			}
			return n;
		}
	}
}
