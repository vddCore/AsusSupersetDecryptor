using AsusSupersetDecryptor;

var path = "C:\\Users\\vdd\\Documents\\Code\\rog\\AC Full Package_1.1.2.2\\SupersetPackage_Core.zip";
var dir = Path.GetDirectoryName(path);
var fname = Path.GetFileNameWithoutExtension(path);
var outPath = Path.Combine(dir!, $"{fname}.reconstructed.zip");

using (var asusZip = new SupersetZip(path))
{
    using (var reconstructedZipStream = new FileStream(outPath, FileMode.Create))
    {
        asusZip.ReconstructZipFile(reconstructedZipStream);
    }
}