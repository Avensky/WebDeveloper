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

// Testing Graph API after login.  See statusChangeCallback() for when this call is made.
function sendTokenToServer() {
  var access_token = FB.getAuthResponse()['accessToken'];
  console.log(access_token)
  console.log('Welcome!  Fetching your information.... ');
  FB.api('/me', function(response) {
    console.log('Successful login for: ' + response.name);
    $.ajax({
      type: 'POST',
      url: '/fbconnect?state={{STATE}}',
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

var fblogout = function(){
  FB.logout(function(response) {
    // Person is now logged out
  });
}
