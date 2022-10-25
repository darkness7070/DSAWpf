
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using System.Windows;
using System.Windows.Forms;
namespace DSAWpf
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class CreateSign : Window
    {
        string pathKey;
        string pathFile;
        string pathSign;
        public CreateSign()
        {
            InitializeComponent();
        }

        private void browseKey(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == System.Windows.Forms.DialogResult.OK) { pathKey = ofd.FileName; boxKey.Text = ofd.FileName; }
            else return;
            
        }
        private void browseFile(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                pathFile = ofd.FileName;
                boxFile.Text = ofd.FileName;
            }
            else
            {
                return;
            }
        }
        private void browseSign(object sender, RoutedEventArgs e)
        {
            FolderBrowserDialog ofd = new FolderBrowserDialog();
            if (ofd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                pathSign = ofd.SelectedPath + @"\Sign";
                boxSign.Text = ofd.SelectedPath + @"\Sign";
            }
            else
            {
                return;
            }
        }

        private void Create(object sender, RoutedEventArgs e)
        {
            byte[] data;
            using (FileStream fs = new FileStream(pathFile, FileMode.Open, FileAccess.Read))
            {
                byte[] buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);
                fs.Close();
                data = buffer;
            }

            TextReader reader = File.OpenText(pathKey);
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();


            Sha256Digest sha256Digest = new Sha256Digest();
            byte[] TheHash = new byte[sha256Digest.GetDigestSize()];
            sha256Digest.BlockUpdate(data, 0, data.Length);
            sha256Digest.DoFinal(TheHash, 0);

            PssSigner Signer = new PssSigner(new RsaEngine(), new Sha256Digest(), sha256Digest.GetDigestSize());
            Signer.Init(true, KeyPair.Private);
            Signer.BlockUpdate(TheHash, 0, TheHash.Length);
            byte[] Signature = Signer.GenerateSignature();
            FileStream SignFile = new FileStream(pathSign, FileMode.Create);
            SignFile.Write(Signature, 0, Signature.Length);
            SignFile.Close();
            Close();
        }
    }
}
