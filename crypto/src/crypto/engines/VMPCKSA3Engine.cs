using System;

namespace Org.BouncyCastle.Crypto.Engines
{
	public class VmpcKsa3Engine
		: VmpcEngine
	{
		public override string AlgorithmName => "VMPC-KSA3";

		protected override void InitKey(byte[] keyBytes, byte[] ivBytes)
		{
			base.InitKey(keyBytes, ivBytes);

            KsaRound(P, ref s, keyBytes);
		}
	}
}
