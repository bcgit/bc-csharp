using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
	/// <summary>
	/// Parameter class for the HKDFBytesGenerator class.
	/// </summary>
	public class HKDFParameters : IDerivationParameters
	{
		/// <summary>
		/// Gets or sets the input keying material or seed.
		/// </summary>
		public byte[] Ikm { get; private set; }

		/// <summary>
		/// The info field, which may be empty (null is converted to empty)
		/// </summary>
		public byte[] Info { get; private set; }

		/// <summary>
		/// The salt, or null if the salt should be generated as a byte array of HashLen zeros.
		/// </summary>
		public byte[] Salt { get; private set; }

		/// <summary>
		/// Sets if step 1: extract has to be skipped or not
		/// </summary>
		public bool SkipExtract { get; private set; }

		public HKDFParameters (byte[] ikm, byte[] salt, byte[] info)
		{
			// validate the input values
			if (ikm == null)
				throw new ArgumentNullException ("ikm");
			if (ikm.Length == 0)
				throw new ArgumentException ("Input key material must not be empty.", "ikm");
			
			this.Ikm = ikm;
			// A null value for info is converted to an empty array
			if (info != null)
				this.Info = info;
			else
				this.Info = new byte[0];

			this.Salt = salt;

			this.SkipExtract = false;
		}

		public static HKDFParameters SkipExtractParameters(byte[] ikm, byte[] info)
		{
			return new HKDFParameters(ikm, null, info) { SkipExtract = true};
		}

		
	}
}

