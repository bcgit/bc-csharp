using System;

namespace Org.BouncyCastle.Crypto.Modes
{
	/// <summary>An IAeadCipher based on an IBlockCipher.</summary>
	public interface IAeadBlockCipher
        : IAeadCipher
	{
        /// <summary>Return the block size for this cipher (in bytes).</summary>
        /// <returns>The block size for this cipher, in bytes.</returns>
        int GetBlockSize();

        /// <summary>The block cipher underlying this algorithm.</summary>
		IBlockCipher UnderlyingCipher { get; }
	}
}
