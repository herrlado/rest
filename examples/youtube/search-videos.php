<?php

include dirname(__FILE__) .'/config.php';

$client  = new RestClient('http://gdata.youtube.com/feeds/api', array(
  '#header' => array(
    'X-GData-Key' => sprintf('key=%s', YOUTUBE_API_KEY), //pass API key
  )
));

$keyword  = 'slash';
$response = $client->get('/videos', array(
    '#query' => array(
      'q'       => $keyword,
      'orderby' => 'viewCount',
      'alt'     => 'json',
    ),
  ), 
  TRUE //decode response
);

$html = array();

$html[] = '<ul>';

foreach ($response->decoded->feed->entry as $entry) {
  $html[] = sprintf('<li>%s</li>', $entry->title->{'$t'});
}

$html[] = '</ul>';

echo implode("\n", $html);

printf('<pre>%s</pre>', print_r($response, TRUE));