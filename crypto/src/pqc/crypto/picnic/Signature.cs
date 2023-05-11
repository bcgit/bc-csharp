namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    internal class Signature
    {
        internal readonly byte[] challengeBits;
        internal readonly byte[] salt;
        internal readonly Proof[] proofs;

        internal Signature(PicnicEngine engine)
        {
            salt = new byte[PicnicEngine.saltSizeBytes];
            challengeBits = new byte[PicnicUtilities.NumBytes(engine.numMPCRounds * 2)];
            proofs = new Proof[engine.numMPCRounds];
            for (int i = 0; i < proofs.Length; i++)
            {
                proofs[i] = new Proof(engine);
            }
        }

        internal class Proof
        {
            internal readonly byte[] seed1;
            internal readonly byte[] seed2;

            internal readonly uint[] inputShare; // Input share of the party which does not derive it from the seed (not included if challenge is 0)

            internal readonly byte[] communicatedBits;
            internal readonly byte[] view3Commitment;
            internal readonly byte[] view3UnruhG; // we include the max length, but we will only serialize the bytes we use

            internal Proof(PicnicEngine engine)
            {
                seed1 = new byte[engine.seedSizeBytes];
                seed2 = new byte[engine.seedSizeBytes];
                inputShare = new uint[engine.stateSizeWords];
                communicatedBits = new byte[engine.andSizeBytes];
                view3Commitment = new byte[engine.digestSizeBytes];
                if (engine.UnruhGWithInputBytes > 0)
                {
                    view3UnruhG = new byte[engine.UnruhGWithInputBytes];
                }
                else
                {
                    view3UnruhG = null;
                }
            }
        }
    }
}
