using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace StringEncryptionExtension
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();

            this.NavigationCacheMode = NavigationCacheMode.Required;
        }

        /// <summary>
        /// Invoked when this page is about to be displayed in a Frame.
        /// </summary>
        /// <param name="e">Event data that describes how this page was reached.
        /// This parameter is typically used to configure the page.</param>
        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            // TODO: Prepare page for display here.

            // TODO: If your application contains multiple pages, ensure that you are
            // handling the hardware Back button by registering for the
            // Windows.Phone.UI.Input.HardwareButtons.BackPressed event.
            // If you are using the NavigationHelper provided by some templates,
            // this event is handled for you.
        }


        private void EncyptionButton_OnClick(object sender, RoutedEventArgs e)
        {
            ResultTB.Text = InputTextBox.Text.EncryptStringSymmetric(PSKTB.Text);
        }

        private void DecryptionButton_OnClick(object sender, RoutedEventArgs e)
        {
            InputTextBox.Text = ResultTB.Text;

            ResultTB.Text = InputTextBox.Text.DecryptStringSymmetric(PSKTB.Text);
        }

        private void GetPSKButton_OnClick(object sender, RoutedEventArgs e)
        {
            //this is used for demonstration purposes only
            //please make sure you are using a truly unique identifier for your app
            PSKTB.Text = Guid.NewGuid().ToString() + "_" + DateTime.Now.Ticks.ToString();
            GetPSKButton.IsEnabled = false;
        }

        private void ClearEncDecButton_OnClick(object sender, RoutedEventArgs e)
        {
            InputTextBox.Text = string.Empty;
            ResultTB.Text = string.Empty;
        }

    }
}
