using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Macs;
using System.Collections.Generic;

namespace Org.BouncyCastle.Crypto.Generators
{
	/// <summary>
	/// HMAC-based Extract-and-Expand Key Derivation Function (HKDF) implemented according to IETF RFC 5869, May 2010 as specified by H. Krawczyk, IBM Research & P. Eronen, Nokia. 
	/// It uses a HMac internally to compute de OKM (output keying material) and is likely to have better security properties than KDF's based on just a hash function.
	/// </summary>
	public class HKDFBytesGenerator : IDerivationFunction
	{
		private HKDFParameters parameters;

		public IDigest Digest { get; private set; }

		/// <summary>
		/// Creates a HKDFBytesGenerator based on the given hash function.
		/// </summary>
		/// <param name="hash">The hash to be used for the key derivation.</param>
		public HKDFBytesGenerator (IDigest hash)
		{
			if (hash == null)
				throw new ArgumentNullException ("hash");
			
			this.Digest = hash;
		}

		/// <summary>
		/// Initialise the byte generator with parameters.
		/// </summary>
		/// <param name="parameters">Parameters for the KDF. Must be of type HKDFParameters.</param>
		public void Init (IDerivationParameters parameters)
		{
			if (parameters == null)
				throw new ArgumentNullException ("parameters");

			this.parameters = parameters as HKDFParameters;
			if (parameters == null)
				throw new ArgumentException ("Parameters of type HKDFParameters needed.", "parameters");
		}

		/// <summary>
		/// Generates the derived key.
		/// </summary>
		/// <returns>The length of the derived key.</returns>
		/// <param name="output">Array where the derived key is to be stored. Must be long enough.</param>
		/// <param name="outOff">Offset in <paramref name="output"/>, where the derived key is written.</param>
		/// <param name="length">Length of the derived key.</param>
		public int GenerateBytes (byte[] output, int outOff, int length)
		{
			if (output == null)
				throw new ArgumentNullException ("output");
			if (outOff < 0)
				throw new ArgumentException ("Offset must not be negative", "outOff");
			if (length < 0)
				throw new ArgumentException ("Length must not be negative.", "length");
			if (output.Length < length + outOff)
				throw new DataLengthException ("Output is not big enough for the specified length.");
			// RFC 5869: HashLen denotes the length of the hash function output in octets
			int hashLen = Digest.GetDigestSize ();
			//RFC 5869: length of output keying material in octets (<= 255*HashLen) 
			if (length > 255 * hashLen)
				throw new DataLengthException ("Length must not exceed 255*HashLen");
			
			//RFC 5869: optional salt value (a non-secret random value); if not provided, it is set to a string of HashLen zeros.
			byte[] salt = parameters.Salt;
			if (salt == null || salt.Length == 0)
				salt = new byte[hashLen];
			
			HMac prf = new HMac (Digest);
			KeyParameter hmacParameters;

			byte[] prk;
			if (parameters.SkipExtract) 
				// No 'extract' step, just use the ikm as the pseudo random key
				prk = parameters.Ikm;
			else {
				// Step 1: Extract
				// RFC 5869: PRK = HMAC-Hash(salt, IKM)
				prk = new byte[hashLen];
				hmacParameters = new KeyParameter (salt);
				prf.Init (hmacParameters);
				prf.BlockUpdate (parameters.Ikm, 0, parameters.Ikm.Length);
				prf.DoFinal (prk, 0);
			}

			//Step 2: Expand
			int blockCount = (int)System.Math.Ceiling((double)length/hashLen);
			//RFC 5869: 
			//  T = T(1) | T(2) | T(3) | ... | T(N)
			// OKM = first L octets of T
			List<byte> okm = new List<byte> ();
			//RFC 5869: T(0) = empty string (zero length)
			byte[] block = new byte[hashLen];
			byte[] lastBlock = new byte[0];
			// RFC 5869:
			// T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
			// T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
			// T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
			//	...
			prf.Reset();
			hmacParameters = new KeyParameter(prk);
			prf.Init(hmacParameters);
			for(int i=1; i <= blockCount; ++i) {
				List<byte> blockData = new List<byte> (lastBlock);
				blockData.AddRange (parameters.Info);
				blockData.AddRange (new byte[]{(byte)i});
				prf.BlockUpdate (blockData.ToArray (), 0, blockData.Count);
				prf.DoFinal (block, 0);
				okm.AddRange (block);
				lastBlock = block;
			}
			okm.CopyTo (0, output, outOff, length);
			//Array.Copy(okm.ToArray(), 0, output, outOff, length);

			//return the length of the data written to output
			return length;
		}
	}
}

