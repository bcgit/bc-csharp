using System;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>Implementation of the VMPC stream cipher with the KSA3 key scheduling algorithm.</summary>
    public class VmpcKsa3Engine
        : VmpcEngine
    {
        /// <inheritdoc/>
        public override string AlgorithmName => "VMPC-KSA3";

        /// <inheritdoc/>
        protected override void InitKey(byte[] keyBytes, byte[] ivBytes)
        {
            base.InitKey(keyBytes, ivBytes);

            KsaRound(P, ref s, keyBytes);
        }
    }
}
