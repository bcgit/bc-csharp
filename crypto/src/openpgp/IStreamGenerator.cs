using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	public interface IStreamGenerator
	{
		[Obsolete("Dispose any opened Stream directly")]
		void Close();
	}
}
