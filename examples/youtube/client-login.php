<?php
session_start('youtube');

include dirname(__FILE__) .'/config.php';

$auth = NULL;

if (!empty($_SESSION['youtube_auth'])) {
  $auth = $_SESSION['youtube_auth'];
}

if ($auth) {
  $client = new RestClient('http://gdata.youtube.com/feeds/api', array(
    '#headers' => array(
      'X-GData-Key'   => 'key='. YOUTUBE_API_KEY, //pass API key
      'Authorization' => 'GoogleLogin '. $auth,   //pass auth token
    ),
    '#query' => array(
      //'key' => YOUTUBE_API_KEY,
    )
  ));
  
  //other code here
  
} else {
  /**
   * http://code.google.com/apis/youtube/2.0/developers_guide_protocol_clientlogin.html#ClientLogin_Authentication
   */
  $client = new RestClient('https://www.google.com/accounts');
  
  $response = $client->post('/ClientLogin', array(
    '#post' => array(
      'Email'   => YOUTUBE_USER,
      'Passwd'  => YOUTUBE_PASS,
      'service' => 'youtube',
      'source'  => 'Test',
    )
  ));
  
  $tokens = explode("\n", trim($response->body));
  $_SESSION['youtube_auth'] = trim(array_pop($tokens));
}