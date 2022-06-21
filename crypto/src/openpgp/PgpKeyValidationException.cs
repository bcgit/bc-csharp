using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>
	/// Thrown if the key checksum is invalid.
	/// </remarks>
#if !PORTABLE
    [Serializable]
#endif
    public class PgpKeyValidationException
		: PgpException
	{
		public PgpKeyValidationException() : base() {}
		public PgpKeyValidationException(string message) : base(message) {}
		public PgpKeyValidationException(string message, Exception exception) : base(message, exception) {}
	}
}
