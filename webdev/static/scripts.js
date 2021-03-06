window.fbAsyncInit = function() {
  FB.init({
    appId      : '599583343779617',
    cookie     : true,                     // Enable cookies to allow the server to access the session.
    status     : true,
    xfbml      : true,                     // Parse social plugins on this webpage.
    version    : 'v5.0'                    // Use this Graph API version for this call.
  });
};


// Load the SDK asynchronously
(function(d, s, id) {
  var js, fjs = d.getElementsByTagName(s)[0];
  if (d.getElementById(id)) return;
  js = d.createElement(s); js.id = id;
  js.src = "https://connect.facebook.net/en_US/sdk.js";
  fjs.parentNode.insertBefore(js, fjs);
}(document, 'script', 'facebook-jssdk'));


function checkLoginState() {
  FB.getLoginStatus(function(response) {
    statusChangeCallback(response);
  });
}

function statusChangeCallback(response) {  // Called with the results from FB.getLoginStatus().
   console.log('statusChangeCallback');
   console.log(response);                   // The current login status of the person.
   if (response.status === 'connected') {   // Logged into your webpage and Facebook.
     sendTokenToServer();
   } else {                                 // Not logged into your webpage or we are unable to tell.
     document.getElementById('status').innerHTML = 'Please log ' +
       'into this webpage.';
   }
 }

function fbLogout() {
  FB.logout(function(response) {
    // Person is now logged out
  });
}


// Testing Graph API after login.  See statusChangeCallback() for when this call is made.
function sendTokenToServer() {
  var access_token = FB.getAuthResponse()['accessToken'];
  console.log(access_token)
  console.log('Welcome!  Fetching your information.... ');
  FB.api('/me', function(response) {
    console.log('Successful login for: ' + response.name);
    $.ajax({
      type: 'POST',
      url: '/fbconnect',
      processData: false,
      data: access_token,
      contentType: 'application/octet-stream; charset=utf-8',
      success: function(result) {
        // Handle or verify the server response if necessary.
        if (result) {
          $('#result').html('Login Successful!</br>'+ result + '</br>Redirecting...')
         setTimeout(function() {
          window.location.href = "/blog";
         }, 4000);
        } else {
          $('#result').html('Failed to make a server-side call. Check your configuration and console.');
        }
      }
    });
  });
}
