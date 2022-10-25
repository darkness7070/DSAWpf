
using Org.BouncyCastle.Crypto;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.IO;
using System.Windows;
using System.Windows.Forms;
namespace DSAWpf
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        public MainWindow()
        {
            InitializeComponent();
        }

        private void createSign(object sender, RoutedEventArgs e)
        {
            new CreateSign().ShowDialog();
        }

        private void verifySign(object sender, RoutedEventArgs e)
        {
            new VerifySign().ShowDialog();
        }

        private void generateKeys(object sender, RoutedEventArgs e)
        {
            string path;
            FolderBrowserDialog dialog = new FolderBrowserDialog();
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK) path = dialog.SelectedPath;
            else return;
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            AsymmetricCipherKeyPair subjKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, 2048);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjKeyPair = keyPairGenerator.GenerateKeyPair();

            using (TextWriter textWriter = new StreamWriter(path + @"\PubKey.pem", false))
            {
                PemWriter pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(subjKeyPair.Public);
                pemWriter.Writer.Flush();
            }
            using (TextWriter textWriter = new StreamWriter(path + @"\PrivKey.pem", false))
            {
                PemWriter pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(subjKeyPair.Private);
                pemWriter.Writer.Flush();
            }
        }
    }
}
