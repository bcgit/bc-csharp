namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    internal class View
    {
        internal uint[] inputShare;
        internal byte[] communicatedBits;
        internal uint[] outputShare;

        internal View(PicnicEngine engine)
        {
            inputShare = new uint[engine.stateSizeBytes];
            communicatedBits = new byte[engine.andSizeBytes];
            outputShare = new uint[engine.stateSizeBytes];
        }
    }
}
