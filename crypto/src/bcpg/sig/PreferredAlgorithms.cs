namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket containing algorithm preferences of the key holder's implementation.</summary>
    /// <remarks>
    /// This class is used to implement:
    /// <list type="bullet">
    /// <item>Preferred Hash Algorithms</item>
    /// <item>Preferred Symmetric Key Algorithms</item>
    /// <item>Preferred Compression Algorithms</item>
    /// </list>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-symmetric-ciphers">
    /// RFC9580 - Preferred Symmetric Ciphers for v1 SEIPD
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-hash-algorithms">
    /// RFC9580 - Preferred Hash Algorithms
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-compression-algor">
    /// RFC9580 - Preferred Compression Algorithms
    /// </see>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.7">
    /// RFC4880 - Preferred Symmetric Algorithms
    /// </see>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.8">
    /// RFC4880 - Preferred Hash Algorithms
    /// </see>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.9">
    /// RFC4880 - Preferred Compression Algorithms
    /// </see>
    /// </para>
    /// </remarks>
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
