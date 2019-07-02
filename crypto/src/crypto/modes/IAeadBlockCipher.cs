using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Modes
{
	/// <summary>
	/// A block cipher mode that includes authenticated encryption with a streaming mode
	/// and optional associated data.</summary>
	/// <see cref="AeadParameters"/>
	public interface IAeadBlockCipher : IAeadCipher
    {
		/// <summary>The block cipher underlying this algorithm.</summary>
		IBlockCipher GetUnderlyingCipher();

		/// <returns>The block size for this cipher, in bytes.</returns>
		int GetBlockSize();
	}
}
