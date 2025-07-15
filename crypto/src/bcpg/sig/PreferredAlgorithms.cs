namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
     * packet giving signature creation time.
     */
    public class PreferredAlgorithms
        : SignatureSubpacket
    {
        private static int[] DataToPrefs(byte[] data)
        {
            int[] prefs = new int[data.Length];
            for (int i = 0; i < prefs.Length; ++i)
            {
                prefs[i] = data[i];
            }
            return prefs;
        }

        private static byte[] PrefsToData(int[] prefs)
        {
            byte[] data = new byte[prefs.Length];
            for (int i = 0; i < prefs.Length; ++i)
            {
                data[i] = (byte)prefs[i];
            }
            return data;
        }

        public PreferredAlgorithms(SignatureSubpacketTag type, bool critical, bool isLongLength, byte[] data)
            : base(type, critical, isLongLength, data)
        {
        }

        public PreferredAlgorithms(SignatureSubpacketTag type, bool critical, int[] preferences)
            : base(type, critical, isLongLength: false, PrefsToData(preferences))
        {
        }

        public int[] GetPreferences() => DataToPrefs(Data);
    }
}
