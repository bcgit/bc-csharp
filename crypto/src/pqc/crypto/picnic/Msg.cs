namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    internal class Msg
    {
        internal byte[][] msgs; // One for each player
        internal int pos;
        internal int unopened; // Index of the unopened party, or -1 if all parties opened (when signing)

        internal Msg(PicnicEngine engine)
        {
            msgs = new byte[engine.numMPCParties][]; // engine.andSizeBytes 
            for (int i = 0; i < engine.numMPCParties; i++)
            {
                msgs[i] = new byte[engine.andSizeBytes];
            }
            pos = 0;
            unopened = -1;
        }
    }
}
