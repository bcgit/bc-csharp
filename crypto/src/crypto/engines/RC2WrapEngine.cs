using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
	/**
	 * Wrap keys according to RFC 3217 - RC2 mechanism
	 */
	public class RC2WrapEngine
		: IWrapper
	{
		/** Field engine */
		private CbcBlockCipher engine;

		/** Field param */
		private ICipherParameters parameters;

		/** Field paramPlusIV */
		private ParametersWithIV paramPlusIV;

		/** Field iv */
		private byte[] iv;

		/** Field forWrapping */
		private bool forWrapping;

		private SecureRandom sr;

		/** Field IV2           */
		private static readonly byte[] IV2 =
		{
			(byte) 0x4a, (byte) 0xdd, (byte) 0xa2,
			(byte) 0x2c, (byte) 0x79, (byte) 0xe8,
			(byte) 0x21, (byte) 0x05
		};

		//
		// checksum digest
		//
		private readonly IDigest sha1 = new Sha1Digest();
		private readonly byte[] digest = new byte[20];

		/**
			* Method init
			*
			* @param forWrapping
			* @param param
			*/
        public virtual void Init(bool forWrapping, ICipherParameters parameters)
		{
			this.forWrapping = forWrapping;
			this.engine = new CbcBlockCipher(new RC2Engine());

			parameters = ParameterUtilities.GetRandom(parameters, out var providedRandom);
			sr = forWrapping ? CryptoServicesRegistrar.GetSecureRandom(providedRandom) : null;

			if (parameters is ParametersWithIV withIV)
			{
				if (!forWrapping)
					throw new ArgumentException("You should not supply an IV for unwrapping");

				this.paramPlusIV = withIV;
				this.iv = withIV.GetIV();
				this.parameters = withIV.Parameters;

				if (this.iv.Length != 8)
					throw new ArgumentException("IV is not 8 octets");
			}
			else
			{
				this.parameters = parameters;

				if (this.forWrapping)
				{
					// Hm, we have no IV but we want to wrap ?!?
					// well, then we have to create our own IV.
					this.iv = new byte[8];
					sr.NextBytes(iv);
					this.paramPlusIV = new ParametersWithIV(this.parameters, this.iv);
				}
			}
		}

		/**
		* Method GetAlgorithmName
		*
		* @return
		*/
        public virtual string AlgorithmName
		{
			get { return "RC2"; }
		}

		/**
		* Method wrap
		*
		* @param in
		* @param inOff
		* @param inLen
		* @return
		*/
        public virtual byte[] Wrap(byte[] input, int inOff, int length)
		{
			if (!forWrapping)
				throw new InvalidOperationException("Not initialized for wrapping");

			int len = (length + 8) & ~7;
			int ivLen = iv.Length;

            // Let TEMP = IV || WKCKS.
            byte[] TEMP = Arrays.CopyOf(iv, ivLen + len + 8);
			TEMP[ivLen] = (byte)length;
			Array.Copy(input, inOff, TEMP, ivLen + 1, length);

            int padLen = len - length - 1;
			if (padLen > 0)
			{
                sr.NextBytes(TEMP, ivLen + len - padLen, padLen);
            }

            // Compute the CMS Key Checksum, (section 5.6.1), call this CKS.
            CalculateCmsKeyChecksum(TEMP, ivLen, len, TEMP, ivLen + len);

            int blockSize = engine.GetBlockSize();

            // Encrypt WKCKS in CBC mode using KEK as the key and IV as the initialization vector.
            {
                engine.Init(true, paramPlusIV);

				int pos = ivLen;
				while (pos < TEMP.Length)
				{
					engine.ProcessBlock(TEMP, pos, TEMP, pos);
					pos += blockSize;
				}

				if (pos != TEMP.Length)
					throw new InvalidOperationException("Not multiple of block length");
			}

			// Reverse the order of the octets in TEMP.
			Array.Reverse(TEMP);

			// Encrypt TEMP in CBC mode using the KEK and an initialization vector
			// of 0x 4a dd a2 2c 79 e8 21 05. The resulting cipher text is the desired
			// result. It is 40 octets long if a 168 bit key is being wrapped.
			{
                engine.Init(true, new ParametersWithIV(this.parameters, IV2));

                int pos = 0;
                while (pos < TEMP.Length)
                {
                    engine.ProcessBlock(TEMP, pos, TEMP, pos);
                    pos += blockSize;
                }

                if (pos != TEMP.Length)
                    throw new InvalidOperationException("Not multiple of block length");
            }

            return TEMP;
		}

		/**
		* Method unwrap
		*
		* @param in
		* @param inOff
		* @param inLen
		* @return
		* @throws InvalidCipherTextException
		*/
        public virtual byte[] Unwrap(byte[] input, int inOff, int length)
		{
			if (forWrapping)
				throw new InvalidOperationException("Not set for unwrapping");
			if (input == null)
				throw new InvalidCipherTextException("Null pointer as ciphertext");
			if (length % engine.GetBlockSize() != 0)
				throw new InvalidCipherTextException("Ciphertext not multiple of " + engine.GetBlockSize());

            /*
			// Check if the length of the cipher text is reasonable given the key
			// type. It must be 40 bytes for a 168 bit key and either 32, 40, or
			// 48 bytes for a 128, 192, or 256 bit key. If the length is not supported
			// or inconsistent with the algorithm for which the key is intended,
			// return error.
			//
			// we do not accept 168 bit keys. it has to be 192 bit.
			int lengthA = (estimatedKeyLengthInBit / 8) + 16;
			int lengthB = estimatedKeyLengthInBit % 8;

			if ((lengthA != keyToBeUnwrapped.Length) || (lengthB != 0)) {
				throw new XMLSecurityException("empty");
			}
			*/

            int blockSize = engine.GetBlockSize();

			byte[] TEMP = new byte[length];

            // Decrypt the cipher text with TRIPLedeS in CBC mode using the KEK
            // and an initialization vector (IV) of 0x4adda22c79e82105. Call the output TEMP.
            {
                engine.Init(false, new ParametersWithIV(this.parameters, IV2));

                int pos = 0;
				while (pos < TEMP.Length)
				{
					engine.ProcessBlock(input, inOff + pos, TEMP, pos);
					pos += blockSize;
				}

                if (pos != TEMP.Length)
                    throw new InvalidOperationException("Not multiple of block length");
            }

            // Reverse the order of the octets in TEMP.
            Array.Reverse(TEMP);

			// Decompose TEMP into IV, the first 8 octets, and LCEKPADICV, the remaining octets.
			this.iv = Arrays.CopyOf(TEMP, 8);

            // Decrypt LCEKPADICV using TRIPLedeS in CBC mode using the KEK and the IV
            // found in the previous step. Call the result WKCKS.
            this.paramPlusIV = new ParametersWithIV(this.parameters, this.iv);

			{
				this.engine.Init(false, this.paramPlusIV);

				int pos = 8;
				while (pos < TEMP.Length)
				{
					engine.ProcessBlock(TEMP, pos, TEMP, pos);
					pos += blockSize;
				}

                if (pos != TEMP.Length)
                    throw new InvalidOperationException("Not multiple of block length");
            }

            // Decompose LCEKPADICV. CKS is the last 8 octets and WK, the wrapped key, are
            // those octets before the CKS.

            // Calculate a CMS Key Checksum, (section 5.6.1), over the WK and compare
            // with the CKS extracted in the above step. If they are not equal, return error.
            if (!CheckCmsKeyChecksum(TEMP, 8, TEMP.Length - 16, TEMP, TEMP.Length - 8))
				throw new InvalidCipherTextException("Checksum inside ciphertext is corrupted");

			int padLen = TEMP.Length - 16 - TEMP[8] - 1;
            if ((padLen & 7) != padLen)
				throw new InvalidCipherTextException("Invalid padding length (" + padLen + ")");

			// CEK is the wrapped key, now extracted for use in data decryption.
			return Arrays.CopyOfRange(TEMP, 9, 9 + TEMP[8]);
		}

		/**
		* Some key wrap algorithms make use of the Key Checksum defined
		* in CMS [CMS-Algorithms]. This is used to provide an integrity
		* check value for the key being wrapped. The algorithm is
		*
		* - Compute the 20 octet SHA-1 hash on the key being wrapped.
		* - Use the first 8 octets of this hash as the checksum value.
		*
		* @param key
		* @return
		* @throws Exception
		* @see http://www.w3.org/TR/xmlenc-core/#sec-CMSKeyChecksum
		*/
		private void CalculateCmsKeyChecksum(byte[] key, int keyOff, int keyLen, byte[] cks, int cksOff)
		{
			sha1.BlockUpdate(key, keyOff, keyLen);
			sha1.DoFinal(digest, 0);

			Array.Copy(digest, 0, cks, cksOff, 8);
		}

		/**
		* @param key
		* @param checksum
		* @return
		* @see http://www.w3.org/TR/xmlenc-core/#sec-CMSKeyChecksum
		*/
		private bool CheckCmsKeyChecksum(byte[] key, int keyOff, int keyLen, byte[] cks, int cksOff)
		{
            sha1.BlockUpdate(key, keyOff, keyLen);
            sha1.DoFinal(digest, 0);

            return Arrays.FixedTimeEquals(8, digest, 0, cks, cksOff);
		}
	}
}
