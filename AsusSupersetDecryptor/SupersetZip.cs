using System.Globalization;
using System.IO.Compression;
using System.Runtime.InteropServices;
using Vanara.PInvoke;

namespace AsusSupersetDecryptor
{
    // SuperSet is how ASUS calls their dogshit installer
    // system. As if InstallShield wasn't already a thing.
    //
    // The only thing that's """Super""" about it is how 
    // fucking dumb it is. Absolute trash.
    //
    // Also, fuck the built-in RSA crypto provider for
    // not supporting block-based decryption. Garbage.
    //
    public class SupersetZip : IDisposable
    {
        private static readonly string _keyString = // lol ASUS, you stupid, fix your shit instead of playing security by obscurity.
            "308204a40201000282010100dbc086cf44ad6e3a0ee0b0a7abd17ec24b542ef600ce365d8868cb08e2ba4b93f21b67f31727144580e14de1e" +
            "edb1ddfae7f164c7de05e13a2c568ca9729e868b1fabb9466b7192fe2e063153c422a3bac8abca3ab9dbd7217e6a2ccb9924adc7c52c01d40" +
            "2d4c4031a9f8905584105142d21432fedce75ce5c9b95160ffa7b6e36ca31f037bbb9196f302eb85e3042ae8c72ff44a4cfcfa075acb60405" +
            "c8404a42e20e79408c71951d0ded0e2b21b8746ef594ed92d3fbcf174f8cb4aaf56d3caa77e34a5058844c49b57eaa81c9fd8dbca58c4287d" +
            "b23517bab063d01ed6e3d0ad1bc8558192e1df375edc9e88db6f1abcd6fee0c4fb673279407e735c749502030100010282010066005392d9b" +
            "9f6b4143bcf43c4c91521727dbcde8b392c9af5ba4ea3ed39b3e3143a0c6215991a1bb8dadb9fc79305a6d204438175dc334ec1fb07cd21a5" +
            "5e2f5a8d9b8c22b1528b9bafb3ce238e42b4383e9d990b0bc8e7b0986970c5a2560549dfcf34c499420f79fdff565f9b5147a6d08477b73d2" +
            "a57408205f6f42336e11d00ddbe0e80b7f217b58a97f06835d9de8e6e1e472df32f1af2dffca1c445ffb3ec27c74133fd5a1dfb9a481554be" +
            "4477de5a66ee9dd1fa005fcb7d8cc5c3719000c37356368d07a064a3b1d7e216a67a000bfaf20c99ad154b89bea4d20f9d7aac5770eef75c8" +
            "fdb5e742497c95a3cacb695f3f2719eda2527c516522e428102818100f7ccaf6d1e147526bb94c00de987c059379c3868fb7a89d269967817" +
            "fca289f5fb1a150a92802dd99da3e3647fd28ed4e1def65bceec701e5868e58454c138d1284f3ca19a6a686aff1cad7301f4a8f4071175121" +
            "1ad08ef7d370d0a1c3d32924b45315df5fa7d7b6e3f8a6bd32248993d17c7883bbf308f6bc53d73cfb6a17902818100e3063a53b5246f6d84" +
            "e4b8c57bc536cedc6bcb5fa324c47093e32293d235daeb88e60866acf27a5ced96b6629804c8810fd771e26fa310ca7091fbf024dc6020d56" +
            "c97b6fa7fe5ef001085db1720671e51fdbecf7e20b64053c8f4d3f112b7ad914e958251fe37b558828e298854586a27f1736b20fca0181217" +
            "0f7a9afde0fd02818100adebdddcaa56157ba000e163625b4367db1e2c8192b008f7c3e0365e2f952d5b966852085f96d3977f8b3dd895d68" +
            "525697b0252a1c35556171b58ac2e88878655d2776dbd619df42b26479f06ea5f83174aeb6e4935b7a5cfaec9da24c3d730d2dfb7ac892ecc" +
            "cfcb2b91cde81c91f3ebeb3ac2a59ca54aa48b857c3977a79102818100cea3688bb0a14d5b1e4f216f7f4ceeaa332f5a99de6124fc635fa6a" +
            "56dfcdf1aec2c9510fff26536187bc9decc07ee88aae6ab1e3406f4cd8ed111c46f88b766ab5c806b686ee9d734f3d522aa5630060513358e" +
            "9f7b1ee8465aef9dca1c035bd49af6b2fbf6acb63fadf5c00ffad5cf2a34379e17145a940e43372f9dcbdff10281800e0a73dc1e9f6ba8c01" +
            "5647777a3e900060569b0d9465963086f2679169ff597bc24b77169265431f35ebb2d82a5dbeb92e99dc0222ca9f4f0e49d797f4e3e17017a" +
            "18b9c390c9b8a79a37af7b5e928cc9d6148eb0cd0ec2f0d633e4989f0a3cf02103fda493895b2ba37bd6836627bdc3c6a44085f7359afdccf" +
            "18a32dc0ccf";

        private static readonly byte[] _keyBytes = _keyString.Chunk(2).Select(
            x => byte.Parse(x, NumberStyles.HexNumber)
        ).ToArray();

        private FileStream _fileStream;
        private ZipArchive _archive;

        private ZipArchiveEntry _encEntry;
        private ZipArchiveEntry _datEntry;

        public SupersetZip(string zipFileName)
        {
            _fileStream = new FileStream(zipFileName, FileMode.Open);
            _archive = new ZipArchive(_fileStream);

            foreach (var entry in _archive.Entries)
            {
                if (Path.GetExtension(entry.FullName) == ".enc")
                {
                    _encEntry = entry;
                }
                else if (Path.GetExtension(entry.FullName) == ".dat")
                {
                    _datEntry = entry;
                }
            }

            if (_encEntry == null || _datEntry == null)
            {
                throw new FormatException("Invalid ASUS ZIP file.");
            }
        }

        public void ReconstructZipFile(Stream outStream)
        {
            using (var encStream = _encEntry.Open())
            {
                using (var centralDirStream = DecryptZipCentralDirectory(encStream))
                {
                    var debug = new FileStream("debug.dec", FileMode.Create);
                    centralDirStream.CopyTo(debug);
                    debug.Dispose();

                    centralDirStream.Seek(0, SeekOrigin.Begin);
                    centralDirStream.CopyTo(outStream);
                }
                
            }
            using (var zipDataStream = _datEntry.Open())
            {
                zipDataStream.CopyTo(outStream);
            }
        }

        private MemoryStream DecryptZipCentralDirectory(Stream zipStream)
        {
            if (!LoadRsaDecryptionKey(out var hprov, out var hcryptkey))
                throw new InvalidOperationException("Unable to load RSA key for whatever reason.");

            using var encStream = new MemoryStream();
            zipStream.CopyTo(encStream);
            encStream.Seek(0, SeekOrigin.Begin);
            
            var ms = new MemoryStream();
            var bytes = new byte[256];
            
            while (encStream.Position < encStream.Length)
            {
                var actualCount = encStream.Read(bytes);
                var final = encStream.Position >= encStream.Length;
                
                if (!AdvApi32.CryptDecrypt(
                        hcryptkey,
                        Crypt32.HCRYPTHASH.NULL,
                        final,
                        0,
                        bytes,
                        ref actualCount
                    ))
                {
                    throw new InvalidOperationException("Decryption failed for whatever reason.");
                }

                ms.Write(bytes[0..actualCount]);
            }

            ms.Seek(0, SeekOrigin.Begin);
            ms.SetLength(ms.Length - 4); // We don't give a single flying fuck about the 4-byte checksum at the end.
            
            AdvApi32.CryptReleaseContext(hprov);
            AdvApi32.CryptDestroyKey(hcryptkey);
            
            return ms;
        }

        private bool LoadRsaDecryptionKey(out AdvApi32.SafeHCRYPTPROV hprov, out Crypt32.HCRYPTKEY key)
        {
            var ret = false;
            key = Crypt32.HCRYPTKEY.NULL;

            if (AdvApi32.CryptAcquireContext(
                    out hprov,
                    null,
                    null,
                    AdvApi32.PROV_RSA_FULL,
                    AdvApi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT
                    | AdvApi32.CryptAcquireContextFlags.CRYPT_SILENT
                ))
            {
                if (ImportRsaKey(hprov.DangerousGetHandle(), out var safeKey))
                {
                    ret = true;
                    key = new Crypt32.HCRYPTKEY(safeKey.DangerousGetHandle());
                }                
            }

            return ret;
        }

        private bool ImportRsaKey(nint hCryptProvider, out Crypt32.SafeHCRYPTKEY hCryptKey)
        {
            var ret = false;
            hCryptKey = Crypt32.SafeHCRYPTKEY.Null;

            if (DecodeKeyObject(out var keyLength, out var keyData))
            {
                ret = AdvApi32.CryptImportKey(
                    hCryptProvider,
                    keyData, keyLength,
                    Crypt32.HCRYPTKEY.NULL,
                    0,
                    out hCryptKey
                );

                Marshal.FreeHGlobal(keyData);
            }

            return ret;
        }

        private bool DecodeKeyObject(out uint rsaKeyLength, out nint rsaKeyData)
        {
            rsaKeyLength = 0;
            rsaKeyData = 0;

            if (Crypt32.CryptDecodeObjectEx(
                    Crypt32.CertEncodingType.X509_ASN_ENCODING | Crypt32.CertEncodingType.PKCS_7_ASN_ENCODING,
                    new Crypt32.SafeOID(43),
                    Marshal.UnsafeAddrOfPinnedArrayElement(_keyBytes, 0),
                    (uint)_keyBytes.Length,
                    0,
                    0,
                    0,
                    ref rsaKeyLength))
            {
                rsaKeyData = Marshal.AllocHGlobal((int)rsaKeyLength);

                if (Crypt32.CryptDecodeObjectEx(
                        Crypt32.CertEncodingType.X509_ASN_ENCODING | Crypt32.CertEncodingType.PKCS_7_ASN_ENCODING,
                        new Crypt32.SafeOID(43),
                        Marshal.UnsafeAddrOfPinnedArrayElement(_keyBytes, 0),
                        (uint)_keyBytes.Length,
                        0,
                        0,
                        rsaKeyData,
                        ref rsaKeyLength))
                {
                    return true;
                }
                else
                {
                    Marshal.FreeHGlobal(rsaKeyData);
                }
            }

            return false;
        }

        public void Dispose()
        {
            _fileStream.Dispose();
            _archive.Dispose();
        }
    }
}