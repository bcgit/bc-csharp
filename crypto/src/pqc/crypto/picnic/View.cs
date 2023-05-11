namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    internal class View
    {
        internal readonly uint[] inputShare;
        internal readonly byte[] communicatedBits;
        internal readonly uint[] outputShare;

        internal View(PicnicEngine engine)
        {
            inputShare = new uint[engine.stateSizeWords];
            communicatedBits = new byte[engine.andSizeBytes];
            outputShare = new uint[engine.stateSizeWords];
        }
    }
}
